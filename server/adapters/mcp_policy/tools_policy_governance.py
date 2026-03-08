"""MCP tools for policy-governance evaluation, delegation, and evidence verification."""

from __future__ import annotations

import json
from typing import Any

from server.metrics import record_mcp_formal_missing_runtime_solver
from server.mcp.api_client import MCPApiClientError, get_api_client
from server.mcp.auth_session import auth_error_payload, enforce_mcp_policy, require_mcp_auth
from server.mcp.execution_policy import ExecutionPolicyError, enforce_execution_policy
from server.mcp.monitoring import emit_failure_alert
from server.mcp.tools_api import MCPToolExecutionError


def _extract_runtime_solver(certificate_payload: dict[str, Any]) -> dict[str, Any]:
    """Extract runtime solver metadata from a serialized decision certificate."""
    proof_payload = certificate_payload.get("proof_payload")
    if not isinstance(proof_payload, dict):
        return {}
    runtime_solver = proof_payload.get("runtime_solver")
    if not isinstance(runtime_solver, dict):
        return {}
    return runtime_solver


def _error_payload(message: str, status_code: int = 422) -> str:
    return json.dumps(
        {
            "success": False,
            "error": message,
            "status_code": status_code,
        },
        indent=2,
    )


def _raise_api_error(operation: str, exc: MCPApiClientError) -> None:
    raise MCPToolExecutionError(
        json.dumps(auth_error_payload(exc, operation), indent=2, default=str)
    ) from exc


def _parse_json_object(value: str, field_name: str) -> dict[str, Any]:
    """Parse JSON object payload with deterministic validation errors."""
    try:
        parsed = json.loads(value) if value else {}
    except json.JSONDecodeError as exc:
        raise MCPToolExecutionError(
            _error_payload(f"Invalid JSON for {field_name}: {exc}")
        ) from exc

    if not isinstance(parsed, dict):
        raise MCPToolExecutionError(_error_payload(f"{field_name} must decode to a JSON object"))
    return parsed


def _parse_json_list(value: str, field_name: str) -> list[Any]:
    """Parse JSON list payload with deterministic validation errors."""
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise MCPToolExecutionError(
            _error_payload(f"Invalid JSON for {field_name}: {exc}")
        ) from exc

    if not isinstance(parsed, list):
        raise MCPToolExecutionError(_error_payload(f"{field_name} must decode to a JSON array"))
    return parsed


def _extract_inadmissible_detail(exc: MCPApiClientError) -> dict[str, Any] | None:
    """Extract standardized inadmissible detail from a REST 403 payload."""
    if exc.status_code != 403:
        return None

    detail = exc.detail
    if not isinstance(detail, dict):
        return None

    nested = detail.get("detail", detail)
    if not isinstance(nested, dict):
        return None

    if nested.get("error") != "inadmissible":
        return None
    return nested


async def _require_auth(
    operation: str,
    params: dict[str, Any],
    *,
    method: str,
    path: str,
) -> None:
    """Require MCP auth/policy checks with consistent execution-policy enforcement."""
    context = {
        "method": method,
        "path": path,
        **params,
    }
    try:
        await require_mcp_auth()
        await enforce_mcp_policy(operation, context)
        await enforce_execution_policy(
            operation,
            method=method,
            context=context,
        )
    except MCPApiClientError as exc:
        raise MCPToolExecutionError(
            json.dumps(auth_error_payload(exc, operation), indent=2, default=str)
        ) from exc
    except ExecutionPolicyError as exc:
        raise MCPToolExecutionError(json.dumps(exc.payload, indent=2, default=str)) from exc


async def mcp_security_evaluate_admissibility(
    principal: str,
    action: str,
    resource: str,
    runtime_context_json: str = "{}",
    *,
    delegation_ref: str = "",
    tenant_id: str = "",
    chain_id: str = "mcp-security-evaluation",
) -> str:
    """Evaluate admissibility theorem and return certificate plus solver metadata."""
    params = {
        "principal": principal,
        "action": action,
        "resource": resource,
    }
    path = "/api/security/admissibility/evaluate"
    await _require_auth(
        "mcp_security_evaluate_admissibility",
        params,
        method="POST",
        path=path,
    )

    runtime_context = _parse_json_object(runtime_context_json, "runtime_context_json")

    body = {
        "principal": principal,
        "action": action,
        "resource": resource,
        "runtime_context": runtime_context,
        "delegation_ref": delegation_ref or None,
        "tenant_id": tenant_id or None,
        "chain_id": chain_id,
    }

    try:
        response = await get_api_client().post(path, body=body)
    except MCPApiClientError as exc:
        inadmissible = _extract_inadmissible_detail(exc)
        if inadmissible is not None:
            certificate = inadmissible.get("certificate", {})
            runtime_solver = inadmissible.get("runtime_solver")
            if not isinstance(runtime_solver, dict):
                runtime_solver = (
                    _extract_runtime_solver(certificate) if isinstance(certificate, dict) else {}
                )
            return json.dumps(
                {
                    "success": False,
                    "error": "inadmissible",
                    "certificate": certificate,
                    "runtime_solver": runtime_solver,
                },
                indent=2,
            )
        _raise_api_error("mcp_security_evaluate_admissibility", exc)

    if not isinstance(response, dict):
        raise MCPToolExecutionError(
            _error_payload("Invalid response from /api/security/admissibility/evaluate", 500)
        )

    certificate = response.get("certificate", {})
    runtime_solver = response.get("runtime_solver")
    if not isinstance(runtime_solver, dict):
        runtime_solver = (
            _extract_runtime_solver(certificate) if isinstance(certificate, dict) else {}
        )
    if not runtime_solver:
        record_mcp_formal_missing_runtime_solver("mcp_security_evaluate_admissibility")
        await emit_failure_alert(
            event_type="mcp_formal_runtime_solver_missing",
            title="Missing runtime solver metadata",
            description=(
                "MCP formal admissibility response did not include runtime_solver metadata."
            ),
            severity="high",
            correlation_id=None,
            details={
                "operation": "mcp_security_evaluate_admissibility",
                "certificate_present": isinstance(certificate, dict),
            },
        )

    return json.dumps(
        {
            "success": bool(response.get("success", True)),
            "certificate": certificate,
            "runtime_solver": runtime_solver,
        },
        indent=2,
        default=str,
    )


async def mcp_security_verify_certificate(
    decision_id: str,
) -> str:
    """Verify persisted decision certificate signature and record verification run."""
    path = "/api/security/certificate/verify"
    await _require_auth(
        "mcp_security_verify_certificate",
        {"decision_id": decision_id},
        method="POST",
        path=path,
    )

    try:
        response = await get_api_client().post(path, body={"decision_id": decision_id})
    except MCPApiClientError as exc:
        _raise_api_error("mcp_security_verify_certificate", exc)
    if not isinstance(response, dict):
        raise MCPToolExecutionError(
            _error_payload("Invalid response from /api/security/certificate/verify", 500)
        )

    return json.dumps(response, indent=2, default=str)


async def mcp_delegation_issue(
    principal: str,
    delegate: str,
    tenant_id: str,
    allowed_actions_json: str,
    resource_scope: str,
    *,
    expires_at: str,
    **legacy_kwargs: Any,
) -> str:
    """Issue delegation grant with attenuation and tenant-bound lineage checks."""
    parent_grant_id = str(legacy_kwargs.pop("parent_grant_id", ""))
    obligations_json = str(legacy_kwargs.pop("obligations_json", "{}"))
    context_constraints_json = str(legacy_kwargs.pop("context_constraints_json", "{}"))
    if legacy_kwargs:
        names = ", ".join(sorted(legacy_kwargs))
        raise MCPToolExecutionError(_error_payload(f"Unsupported delegation options: {names}"))

    params = {
        "principal": principal,
        "delegate": delegate,
        "tenant_id": tenant_id,
        "resource_scope": resource_scope,
    }
    path = "/api/security/delegation/issue"
    await _require_auth("mcp_delegation_issue", params, method="POST", path=path)

    allowed_actions = _parse_json_list(allowed_actions_json, "allowed_actions_json")
    obligations = _parse_json_object(obligations_json, "obligations_json")
    constraints = _parse_json_object(context_constraints_json, "context_constraints_json")

    try:
        response = await get_api_client().post(
            path,
            body={
                "principal": principal,
                "delegate": delegate,
                "tenant_id": tenant_id,
                "allowed_actions": [str(value) for value in allowed_actions],
                "resource_scope": resource_scope,
                "expires_at": expires_at,
                "parent_grant_id": parent_grant_id or None,
                "obligations": obligations,
                "context_constraints": constraints,
            },
        )
    except MCPApiClientError as exc:
        _raise_api_error("mcp_delegation_issue", exc)
    if not isinstance(response, dict):
        raise MCPToolExecutionError(
            _error_payload("Invalid response from /api/security/delegation/issue", 500)
        )

    return json.dumps(response, indent=2, default=str)


async def mcp_delegation_revoke(
    grant_id: str,
    tenant_id: str,
    reason: str,
    transitive: bool = True,
) -> str:
    """Revoke delegation grant and propagate revocation transitively."""
    params = {
        "grant_id": grant_id,
        "tenant_id": tenant_id,
        "reason": reason,
        "transitive": transitive,
    }
    path = "/api/security/delegation/revoke"
    await _require_auth("mcp_delegation_revoke", params, method="POST", path=path)

    try:
        response = await get_api_client().post(
            path,
            body={
                "grant_id": grant_id,
                "tenant_id": tenant_id,
                "reason": reason,
                "transitive": transitive,
            },
        )
    except MCPApiClientError as exc:
        _raise_api_error("mcp_delegation_revoke", exc)
    if not isinstance(response, dict):
        raise MCPToolExecutionError(
            _error_payload("Invalid response from /api/security/delegation/revoke", 500)
        )

    return json.dumps(response, indent=2, default=str)


async def mcp_counterfactual_verify(
    principal: str,
    steps_json: str,
    risk_tier: str = "high",
    tenant_id: str = "",
    verification_grant_token: str = "",
) -> str:
    """Run bounded counterfactual safety verification for proposed multi-step plan."""
    path = "/api/security/counterfactual/verify"
    await _require_auth(
        "mcp_counterfactual_verify",
        {
            "principal": principal,
            "risk_tier": risk_tier,
            "tenant_id": tenant_id,
            "verification_grant_token_present": bool(verification_grant_token),
        },
        method="POST",
        path=path,
    )

    steps = _parse_json_list(steps_json, "steps_json")
    if not all(isinstance(step, dict) for step in steps):
        raise MCPToolExecutionError(_error_payload("Each step must be a JSON object"))

    try:
        response = await get_api_client().post(
            path,
            body={
                "principal": principal,
                "steps": [dict(step) for step in steps],
                "risk_tier": risk_tier,
                "tenant_id": tenant_id or None,
                "verification_grant_token": verification_grant_token or None,
            },
        )
    except MCPApiClientError as exc:
        _raise_api_error("mcp_counterfactual_verify", exc)
    if not isinstance(response, dict):
        raise MCPToolExecutionError(
            _error_payload("Invalid response from /api/security/counterfactual/verify", 500)
        )

    return json.dumps(response, indent=2, default=str)


async def mcp_evidence_verify_chain(chain_id: str = "global") -> str:
    """Verify immutable evidence-chain integrity for given chain identifier."""
    client = get_api_client()
    path = client.path_with_segments("/api/security/evidence/chain", chain_id)
    await _require_auth(
        "mcp_evidence_verify_chain",
        {"chain_id": chain_id},
        method="GET",
        path=path,
    )

    try:
        response = await client.get(path)
    except MCPApiClientError as exc:
        _raise_api_error("mcp_evidence_verify_chain", exc)
    if not isinstance(response, dict):
        raise MCPToolExecutionError(
            _error_payload("Invalid response from /api/security/evidence/chain/{chain_id}", 500)
        )

    return json.dumps(response, indent=2, default=str)
