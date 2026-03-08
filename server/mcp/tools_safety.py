"""MCP safety and runtime introspection tools (minimal policy adapter surface)."""

from __future__ import annotations

import json
from typing import NoReturn

from .api_client import MCPApiClientError
from .auth_session import auth_error_payload, require_mcp_auth
from .guardrails import get_guardrails_status
from .tools_api import MCPToolExecutionError


def _api_error_response(action: str, exc: MCPApiClientError) -> NoReturn:
    raise MCPToolExecutionError(json.dumps(auth_error_payload(exc, action), indent=2, default=str))


async def mcp_guardrails_status() -> str:
    """View current MCP guardrails configuration and immutable safety settings."""
    try:
        await require_mcp_auth()
    except MCPApiClientError as exc:
        _api_error_response("mcp_guardrails_status", exc)

    status = get_guardrails_status()
    return json.dumps(
        {
            "success": True,
            "guardrails": status,
            "note": (
                "Guardrails are human-controlled runtime safety settings; "
                "AI operators cannot modify these values directly."
            ),
        },
        indent=2,
    )


__all__ = ["mcp_guardrails_status"]
