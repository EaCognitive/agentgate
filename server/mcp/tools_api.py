"""Shared helpers and minimal core API bridge MCP tools."""

from __future__ import annotations

import json
from typing import Any, NoReturn

from .api_client import MCPApiClientError, get_api_client
from .execution_policy import ExecutionPolicyError, enforce_execution_policy
from .auth_session import (
    auth_error_payload,
    enforce_mcp_policy,
    require_mcp_auth,
)


def _dump(payload: Any) -> str:
    return json.dumps(payload, indent=2, default=str)


class MCPToolExecutionError(RuntimeError):
    """Raised to force MCP tool calls to return `isError=true`."""


def _raise_tool_error(
    operation: str,
    message: str,
    *,
    status_code: int = 400,
    details: Any = None,
) -> NoReturn:
    payload = {
        "success": False,
        "operation": operation,
        "error": message,
        "status_code": status_code,
        "details": details,
    }
    raise MCPToolExecutionError(_dump(payload))


def _raise_api_error(operation: str, exc: MCPApiClientError) -> NoReturn:
    payload = auth_error_payload(exc, operation)
    raise MCPToolExecutionError(_dump(payload))


def _raise_execution_policy_error(exc: ExecutionPolicyError) -> NoReturn:
    raise MCPToolExecutionError(_dump(exc.payload))


async def _call_get(
    operation: str,
    path: str,
    params: dict[str, Any] | None = None,
    require_auth: bool = True,
) -> str:
    try:
        if require_auth:
            await require_mcp_auth()
            context = {"method": "GET", "path": path, "params": params or {}}
            await enforce_mcp_policy(operation, context)
            await enforce_execution_policy(
                operation,
                method="GET",
                context=context,
            )
        result = await get_api_client().get(path, params=params)
        return _dump(result)
    except MCPApiClientError as exc:
        _raise_api_error(operation, exc)
    except ExecutionPolicyError as exc:
        _raise_execution_policy_error(exc)


async def _call_post(
    operation: str,
    path: str,
    body: dict[str, Any] | None = None,
    require_auth: bool = True,
) -> str:
    try:
        if require_auth:
            await require_mcp_auth()
            context = {"method": "POST", "path": path, "body": body or {}}
            await enforce_mcp_policy(operation, context)
            await enforce_execution_policy(
                operation,
                method="POST",
                context=context,
            )
        result = await get_api_client().post(path, body=body)
        return _dump(result)
    except MCPApiClientError as exc:
        _raise_api_error(operation, exc)
    except ExecutionPolicyError as exc:
        _raise_execution_policy_error(exc)


async def _call_put(
    operation: str,
    path: str,
    body: dict[str, Any] | None = None,
    require_auth: bool = True,
) -> str:
    try:
        if require_auth:
            await require_mcp_auth()
            context = {"method": "PUT", "path": path, "body": body or {}}
            await enforce_mcp_policy(operation, context)
            await enforce_execution_policy(
                operation,
                method="PUT",
                context=context,
            )
        result = await get_api_client().put(path, body=body)
        return _dump(result)
    except MCPApiClientError as exc:
        _raise_api_error(operation, exc)
    except ExecutionPolicyError as exc:
        _raise_execution_policy_error(exc)


async def _call_delete(
    operation: str,
    path: str,
    params: dict[str, Any] | None = None,
    require_auth: bool = True,
) -> str:
    try:
        if require_auth:
            await require_mcp_auth()
            context = {"method": "DELETE", "path": path, "params": params or {}}
            await enforce_mcp_policy(operation, context)
            await enforce_execution_policy(
                operation,
                method="DELETE",
                context=context,
            )
        result = await get_api_client().delete(path, params=params)
        return _dump(result)
    except MCPApiClientError as exc:
        _raise_api_error(operation, exc)
    except ExecutionPolicyError as exc:
        _raise_execution_policy_error(exc)


# ---------------------------------------------------------------------------
# Minimal core API tools retained after hard pivot
# ---------------------------------------------------------------------------


async def mcp_login(
    email: str,
    password: str,
    totp_code: str = "",
    captcha_token: str = "",
) -> str:
    """Authenticate MCP session."""
    try:
        client = get_api_client()
        try:
            setup_resp = await client.get("/api/setup/status")
            if setup_resp.get("setup_required"):
                return _dump(
                    {
                        "status": "setup_required",
                        "message": (
                            "Initial setup has not been completed. "
                            "Complete browser setup before MCP authentication."
                        ),
                        "setup_url": "/api/setup/status",
                    }
                )
        except MCPApiClientError:
            pass

        result = await client.login(
            email=email,
            password=password,
            totp_code=totp_code or None,
            captcha_token=captcha_token or None,
        )
        if result.get("mfa_required"):
            return _dump(
                {
                    "status": "mfa_required",
                    "methods": result.get("methods", []),
                    "detail": result.get("detail", "MFA required"),
                }
            )
        return _dump(
            {
                "status": "authenticated",
                "token_type": result.get("token_type", "bearer"),
                "expires_in": result.get("expires_in"),
                "user": result.get("user", {}),
            }
        )
    except MCPApiClientError as exc:
        _raise_api_error("mcp_login", exc)


async def mcp_logout() -> str:
    """Terminate MCP session."""
    try:
        await require_mcp_auth()
        result = await get_api_client().logout()
        return _dump(result)
    except MCPApiClientError as exc:
        _raise_api_error("mcp_logout", exc)


async def mcp_whoami() -> str:
    """Get authenticated session profile."""
    return await _call_get("mcp_whoami", "/api/auth/me")


async def mcp_pii_session_create(
    session_id: str,
    user_id: str,
    purpose: str = "",
    agent_id: str = "mcp-session",
) -> str:
    """Create scoped PII session."""
    body = {
        "session_id": session_id,
        "user_id": user_id,
        "purpose": purpose or None,
        "agent_id": agent_id or None,
    }
    return await _call_post("mcp_pii_session_create", "/api/pii/sessions", body=body)


async def mcp_pii_redact(
    session_id: str,
    text: str,
    score_threshold: float = 0.4,
    language: str = "",
) -> str:
    """Redact PII text through server-scoped vault."""
    body: dict[str, object] = {
        "session_id": session_id,
        "text": text,
        "score_threshold": score_threshold,
    }
    if language:
        body["language"] = language
    return await _call_post("mcp_pii_redact", "/api/pii/redact", body=body)


async def mcp_pii_restore(
    session_id: str,
    text: str,
) -> str:
    """Restore tokenized PII text in scoped session."""
    return await _call_post(
        "mcp_pii_restore",
        "/api/pii/restore",
        body={"session_id": session_id, "text": text},
    )


async def mcp_pii_session_clear(session_id: str) -> str:
    """Clear scoped PII session and mappings."""
    client = get_api_client()
    path = client.path_with_segments("/api/pii/sessions", session_id)
    return await _call_delete("mcp_pii_session_clear", path)


__all__ = [
    "MCPToolExecutionError",
    "_dump",
    "_raise_tool_error",
    "_raise_api_error",
    "_call_get",
    "_call_post",
    "_call_put",
    "_call_delete",
    "mcp_login",
    "mcp_logout",
    "mcp_whoami",
    "mcp_pii_session_create",
    "mcp_pii_redact",
    "mcp_pii_restore",
    "mcp_pii_session_clear",
]
