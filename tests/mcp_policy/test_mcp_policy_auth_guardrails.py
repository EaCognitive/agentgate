"""Authentication and guardrail enforcement tests for MCP policy-governance tools."""

from __future__ import annotations

import json

import pytest

from server.mcp.tools_api import MCPToolExecutionError, mcp_whoami
from server.mcp.tools_governance import apply_policy
from server.mcp.tools_safety import mcp_guardrails_status


@pytest.mark.asyncio
async def test_fake_token_fails_authenticated_read_tools(mcp_local_client) -> None:
    """Token presence alone must not authorize authenticated MCP tools."""
    client, _ = mcp_local_client
    original_token = client.token
    client.token = "invalid.token.payload"

    with pytest.raises(MCPToolExecutionError) as whoami_exc:
        await mcp_whoami()
    whoami_payload = json.loads(str(whoami_exc.value))
    assert whoami_payload["status_code"] == 401
    assert whoami_payload["operation"] == "mcp_whoami"

    with pytest.raises(MCPToolExecutionError) as guardrails_exc:
        await mcp_guardrails_status()
    guardrails_payload = json.loads(str(guardrails_exc.value))
    assert guardrails_payload["status_code"] == 401
    assert guardrails_payload["operation"] == "mcp_guardrails_status"

    client.token = original_token


@pytest.mark.asyncio
async def test_apply_policy_requires_guardrail_approval(mcp_local_client) -> None:
    """High-impact policy application must enforce preview-confirm guardrail flow."""
    _ = mcp_local_client

    raw = await apply_policy(
        policy_json=json.dumps(
            {
                "pre_rules": [{"type": "ip_deny", "cidr": "10.10.0.0/16"}],
                "post_rules": [],
            }
        )
    )

    payload = json.loads(raw)
    assert payload["success"] is False
    assert isinstance(payload.get("preview_token"), str)
    assert payload["preview_token"]
    assert "Re-run with confirm=true" in payload["message"]
