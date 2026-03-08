"""Helpers for strict MCP authentication and policy gating."""

from __future__ import annotations

import hashlib
import os
import time
from typing import Any

from server.metrics import (
    record_mcp_auth_validation_failure,
    record_mcp_policy_missing_fail_closed,
)

from .api_client import MCPApiClientError, get_api_client
from .monitoring import emit_failure_alert


_AUTH_VALIDATE_TTL_SECONDS = float(os.environ.get("MCP_AUTH_VALIDATE_TTL_SECONDS", "30"))
_auth_validation_cache: dict[str, Any] = {
    "expires_at": 0.0,
    "token_fingerprint": None,
}


def _token_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]


def reset_auth_validation_cache() -> None:
    """Clear the cached authentication validation state."""
    _auth_validation_cache["expires_at"] = 0.0
    _auth_validation_cache["token_fingerprint"] = None


def _auth_cache_is_valid(current_fingerprint: str | None) -> bool:
    expires_at = float(_auth_validation_cache.get("expires_at", 0.0))
    cached_fingerprint = _auth_validation_cache.get("token_fingerprint")
    if expires_at <= time.monotonic():
        return False
    return bool(current_fingerprint and cached_fingerprint == current_fingerprint)


def _set_auth_cache(current_fingerprint: str) -> None:
    _auth_validation_cache["token_fingerprint"] = current_fingerprint
    _auth_validation_cache["expires_at"] = time.monotonic() + _AUTH_VALIDATE_TTL_SECONDS


async def require_mcp_auth(validate_remote: bool = True) -> None:
    """Ensure MCP session is authenticated before tool/resource execution."""
    client = get_api_client()
    await client.ensure_authenticated(validate_remote=False)

    if not validate_remote:
        return

    token = client.token
    if not token:
        raise MCPApiClientError(
            401,
            "MCP client not authenticated. Call mcp_login or set MCP_AUTH_TOKEN.",
        )

    current_fingerprint = _token_fingerprint(token)
    if _auth_cache_is_valid(current_fingerprint):
        return

    try:
        await client.whoami()
    except MCPApiClientError as exc:
        record_mcp_auth_validation_failure()
        await emit_failure_alert(
            event_type="mcp_auth_validation_failure",
            title="MCP auth validation failed",
            description="Remote token validation failed during MCP authentication check.",
            severity="high",
            correlation_id=None,
            details={
                "status_code": exc.status_code,
                "message": exc.message,
            },
        )
        raise
    _set_auth_cache(current_fingerprint)


_POLICY_BYPASS_OPERATIONS = {
    # auth bootstrap/session lifecycle
    "mcp_login",
    "mcp_logout",
    "mcp_whoami",
    # policy management tools must stay accessible to avoid lockout
    "mcp_policies_list",
    "mcp_policies_create",
    "mcp_policies_evaluate",
    "apply_policy",
    "unlock_policy",
}


def _configured_policy_set_id() -> str | None:
    configured = os.environ.get("MCP_POLICY_SET_ID", "").strip()
    return configured or None


_POLICY_CACHE_TTL_SECONDS = float(os.environ.get("MCP_POLICY_CACHE_TTL_SECONDS", "10"))
_cached_policy_selection: dict[str, Any] = {
    "expires_at": 0.0,
    "has_policies": None,
    "selected_policy_id": None,
}


def _get_cached_policy_selection() -> tuple[bool, str | None] | None:
    if _cached_policy_selection["expires_at"] <= time.monotonic():
        return None
    has_policies = _cached_policy_selection["has_policies"]
    if has_policies is None:
        return None
    return bool(has_policies), _cached_policy_selection["selected_policy_id"]


def _set_cached_policy_selection(
    has_policies: bool,
    selected_policy_id: str | None,
) -> None:
    _cached_policy_selection["has_policies"] = has_policies
    _cached_policy_selection["selected_policy_id"] = selected_policy_id
    _cached_policy_selection["expires_at"] = time.monotonic() + _POLICY_CACHE_TTL_SECONDS


def reset_policy_cache() -> None:
    """Clear the cached policy selection state."""
    _cached_policy_selection["expires_at"] = 0.0
    _cached_policy_selection["has_policies"] = None
    _cached_policy_selection["selected_policy_id"] = None


def _agentgate_env() -> str:
    return os.environ.get("AGENTGATE_ENV", "development").strip().lower()


def _is_strict_policy_environment() -> bool:
    return _agentgate_env() in {"staging", "production"}


def _allow_missing_policy_bypass() -> bool:
    configured = os.environ.get("MCP_POLICY_ALLOW_MISSING", "").strip().lower()
    if configured:
        return configured in {"1", "true", "yes", "on"}
    return not _is_strict_policy_environment()


async def _emit_policy_audit_event(
    *,
    event_type: str,
    operation: str,
    outcome: str,
    details: dict[str, Any],
) -> None:
    client = get_api_client()
    try:
        await client.post(
            "/api/audit",
            body={
                "event_type": event_type,
                "tool": operation,
                "result": outcome,
                "details": details,
            },
        )
    except MCPApiClientError:
        return


async def _resolve_policy_set_id(
    client,
    configured_policy: str | None,
    operation: str,
    inputs: dict[str, Any] | None,
) -> str | None:
    """Resolve the policy set ID to evaluate for an MCP operation.

    Handles environment-variable configuration, cache lookups, and
    remote policy listing with fail-closed semantics.

    Args:
        client: Authenticated MCP API client.
        configured_policy: Explicit policy set ID from environment,
            or ``None``.
        operation: MCP operation name (for audit events).
        inputs: Operation inputs (for audit event context).

    Returns:
        The resolved policy set ID string, or ``None`` to signal
        that enforcement should be skipped entirely.

    Raises:
        MCPApiClientError: On invalid API responses or fail-closed
            denial when no policy set is loaded in strict environments.
    """
    if configured_policy:
        return configured_policy

    cached = _get_cached_policy_selection()
    if cached is not None:
        has_policies, cached_id = cached
        if not has_policies:
            return None
        return cached_id

    policy_listing = await client.get("/api/policies")
    if not isinstance(policy_listing, dict):
        raise MCPApiClientError(
            500,
            "Invalid response while listing policies",
            policy_listing,
        )

    loaded = policy_listing.get("loaded_policies", [])
    if not isinstance(loaded, list):
        raise MCPApiClientError(
            500,
            "Invalid policy listing format",
            policy_listing,
        )

    if not loaded:
        await _handle_no_loaded_policies(
            operation,
            inputs,
        )
        return None

    selected = _select_from_db_policies(
        policy_listing,
        loaded,
    )
    _set_cached_policy_selection(
        has_policies=True,
        selected_policy_id=selected,
    )
    return selected


async def _handle_no_loaded_policies(
    operation: str,
    inputs: dict[str, Any] | None,
) -> None:
    """Handle the case when no policies are loaded.

    Caches the empty-policy state and either bypasses enforcement
    or raises a fail-closed error depending on environment config.

    Args:
        operation: MCP operation name (for audit events).
        inputs: Operation inputs (for audit event context).

    Returns:
        None (signals enforcement should be skipped) when bypass
        is allowed.

    Raises:
        MCPApiClientError: When fail-closed is triggered.
    """
    _set_cached_policy_selection(
        has_policies=False,
        selected_policy_id=None,
    )
    if _allow_missing_policy_bypass():
        await _emit_policy_audit_event(
            event_type="MCP_POLICY_BYPASS_MISSING_POLICY",
            operation=operation,
            outcome="bypassed",
            details={
                "reason": "missing_policy_set",
                "environment": _agentgate_env(),
                "request_context": inputs or {},
            },
        )
        return None
    await _emit_policy_audit_event(
        event_type="MCP_POLICY_DENY_MISSING_POLICY",
        operation=operation,
        outcome="denied",
        details={
            "reason": "missing_policy_set",
            "environment": _agentgate_env(),
            "request_context": inputs or {},
        },
    )
    record_mcp_policy_missing_fail_closed()
    await emit_failure_alert(
        event_type="mcp_policy_missing_fail_closed",
        title="MCP policy fail-closed triggered",
        description=(
            "MCP mutating operation was denied because no "
            "active policy set is loaded in strict environment."
        ),
        severity="critical",
        correlation_id=None,
        details={
            "operation": operation,
            "environment": _agentgate_env(),
        },
    )
    raise MCPApiClientError(
        503,
        "Policy enforcement failed closed: no active policy set loaded",
        {
            "operation": operation,
            "environment": _agentgate_env(),
            "reason": "missing_policy_set",
        },
    )


def _select_from_db_policies(
    policy_listing: dict[str, Any],
    loaded: list[Any],
) -> str | None:
    """Select the best policy set ID from a policy listing response.

    Prefers the newest loaded DB-backed policy set.  Falls back to
    the first entry in the ``loaded_policies`` list.

    Args:
        policy_listing: Full policy listing response dict.
        loaded: Non-empty list of loaded policy identifiers.

    Returns:
        Selected policy set ID string, or None if no match found.
    """
    selected_policy_id: str | None = None
    db_policies = policy_listing.get("db_policies", [])
    if isinstance(db_policies, list):
        loaded_db = [
            p
            for p in db_policies
            if isinstance(p, dict)
            and p.get("loaded") is True
            and isinstance(p.get("policy_set_id"), str)
        ]
        if loaded_db:
            loaded_db.sort(
                key=lambda p: int(p.get("db_id", 0) or 0),
                reverse=True,
            )
            selected_policy_id = str(
                loaded_db[0]["policy_set_id"],
            )
    if selected_policy_id is None and loaded:
        selected_policy_id = str(loaded[0])
    return selected_policy_id


async def enforce_mcp_policy(
    operation: str,
    inputs: dict[str, Any] | None = None,
) -> None:
    """Enforce loaded policy rules against an MCP operation.

    Behavior:
    - If no policy sets are loaded, enforcement is skipped.
    - If MCP_POLICY_SET_ID is configured, that policy is used.
    - Otherwise, enforce the newest loaded DB-backed policy set.
    """
    if operation in _POLICY_BYPASS_OPERATIONS:
        return

    client = get_api_client()
    await client.ensure_authenticated(validate_remote=False)

    configured_policy = _configured_policy_set_id()
    selected_policy_id = await _resolve_policy_set_id(
        client,
        configured_policy,
        operation,
        inputs,
    )
    if selected_policy_id is None:
        return

    evaluation = await client.post(
        "/api/policies/evaluate",
        body={
            "policy_set_id": selected_policy_id,
            "request_context": {
                "request": {
                    "tool": operation,
                    "inputs": inputs or {},
                }
            },
        },
    )
    if not isinstance(evaluation, dict):
        raise MCPApiClientError(
            500,
            "Invalid policy evaluation response",
            evaluation,
        )

    if not bool(evaluation.get("allowed", False)):
        reason = str(
            evaluation.get("reason", "Policy denied operation"),
        )
        await _emit_policy_audit_event(
            event_type="MCP_POLICY_DENY",
            operation=operation,
            outcome="denied",
            details={
                "reason": reason,
                "policy_set_id": selected_policy_id,
                "request_context": inputs or {},
            },
        )
        raise MCPApiClientError(
            403,
            f"Policy denied '{operation}': {reason}",
            evaluation,
        )


def auth_error_payload(exc: MCPApiClientError, operation: str) -> dict[str, Any]:
    """Build a consistent JSON payload for auth/API failures."""
    return {
        "success": False,
        "operation": operation,
        "error": exc.message,
        "status_code": exc.status_code,
        "details": exc.detail,
    }
