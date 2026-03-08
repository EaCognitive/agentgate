"""Contract tests for the MCP policy-governance adapter surface."""

from __future__ import annotations

import json

import pytest

from server.adapters.mcp_policy.tools_policy_governance import (
    mcp_security_evaluate_admissibility,
    mcp_security_verify_certificate,
)
from server.mcp.tools_async import mcp_check_job_status, mcp_list_jobs


@pytest.mark.asyncio
async def test_formal_evaluate_uses_canonical_policy_governance_route(mcp_local_client) -> None:
    """Formal evaluation must route through canonical policy-governance REST path."""
    _client, paths = mcp_local_client
    paths.clear()

    raw = await mcp_security_evaluate_admissibility(
        principal="agent:mcp-policy",
        action="config:read",
        resource="tenant/default/config",
        runtime_context_json=(
            '{"authenticated": true, "direct_access": true, '
            '"direct_permit": true, "execution_phase": "confirm", '
            '"preview_confirmed": true}'
        ),
    )

    payload = json.loads(raw)
    assert payload["success"] is True
    assert isinstance(payload.get("runtime_solver"), dict)
    assert payload["runtime_solver"].get("solver_backend") in {"z3", "python+z3", "python"}
    assert "/api/security/admissibility/evaluate" in paths


@pytest.mark.asyncio
async def test_formal_certificate_verify_uses_canonical_policy_governance_route(
    mcp_local_client,
) -> None:
    """Certificate verification must route through canonical REST path."""
    _client, paths = mcp_local_client
    paths.clear()

    eval_raw = await mcp_security_evaluate_admissibility(
        principal="agent:mcp-policy",
        action="config:read",
        resource="tenant/default/config",
        runtime_context_json=(
            '{"authenticated": true, "direct_access": true, "direct_permit": true}'
        ),
    )
    decision_id = json.loads(eval_raw)["certificate"]["decision_id"]

    verify_raw = await mcp_security_verify_certificate(decision_id=decision_id)
    verify_payload = json.loads(verify_raw)

    assert verify_payload["success"] is True
    assert "/api/security/certificate/verify" in paths


@pytest.mark.asyncio
async def test_async_job_tools_return_tool_envelopes(mcp_local_client) -> None:
    """Async job tools must return deterministic ToolEnvelope payloads."""
    _ = mcp_local_client

    list_raw = await mcp_list_jobs(limit=10, offset=0)
    list_payload = json.loads(list_raw)
    assert list_payload["success"] is True
    assert list_payload["operation"] == "mcp_list_jobs"
    assert list_payload["mode"] == "sync"
    assert "jobs" in list_payload["result"]

    unknown_raw = await mcp_check_job_status("job-does-not-exist")
    unknown_payload = json.loads(unknown_raw)
    assert unknown_payload["success"] is False
    assert unknown_payload["operation"] == "mcp_check_job_status"
    assert unknown_payload["mode"] == "sync"
    assert unknown_payload["error"]["status_code"] == 404
