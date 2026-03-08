"""FastMCP server instance and minimal policy-governance tool wiring."""

from __future__ import annotations

import logging
from importlib import import_module

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

logger = logging.getLogger(__name__)

READONLY = ToolAnnotations(readOnlyHint=True)
DESTRUCTIVE = ToolAnnotations(destructiveHint=True)
DESTRUCTIVE_IDEMPOTENT = ToolAnnotations(destructiveHint=True, idempotentHint=True)
_TOOL_MODULE_NAMES = {
    "tools_api": "server.mcp.tools_api",
    "tools_governance": "server.mcp.tools_governance",
    "tools_safety": "server.mcp.tools_safety",
    "tools_async": "server.mcp.tools_async",
    "tools_policy_governance": "server.adapters.mcp_policy.tools_policy_governance",
}
_TOOL_SPECS = (
    ("tools_api", "mcp_login", DESTRUCTIVE_IDEMPOTENT),
    ("tools_api", "mcp_logout", DESTRUCTIVE),
    ("tools_api", "mcp_whoami", READONLY),
    ("tools_policy_governance", "mcp_security_evaluate_admissibility", DESTRUCTIVE_IDEMPOTENT),
    ("tools_policy_governance", "mcp_security_verify_certificate", DESTRUCTIVE_IDEMPOTENT),
    ("tools_policy_governance", "mcp_evidence_verify_chain", READONLY),
    ("tools_policy_governance", "mcp_counterfactual_verify", DESTRUCTIVE),
    ("tools_policy_governance", "mcp_delegation_issue", DESTRUCTIVE),
    ("tools_policy_governance", "mcp_delegation_revoke", DESTRUCTIVE),
    ("tools_governance", "parse_nl_policy", READONLY),
    ("tools_governance", "simulate_policy", READONLY),
    ("tools_governance", "apply_policy", DESTRUCTIVE),
    ("tools_governance", "unlock_policy", DESTRUCTIVE),
    ("tools_api", "mcp_pii_session_create", DESTRUCTIVE),
    ("tools_api", "mcp_pii_redact", DESTRUCTIVE),
    ("tools_api", "mcp_pii_restore", READONLY),
    ("tools_api", "mcp_pii_session_clear", DESTRUCTIVE_IDEMPOTENT),
    ("tools_safety", "mcp_guardrails_status", READONLY),
    ("tools_async", "mcp_check_job_status", READONLY),
    ("tools_async", "mcp_list_jobs", READONLY),
)


def _titleize(identifier: str, *, strip_prefix: str = "") -> str:
    """Convert snake_case identifiers into UI-friendly MCP titles."""
    if strip_prefix and identifier.startswith(strip_prefix):
        identifier = identifier[len(strip_prefix) :]
    return identifier.replace("_", " ").strip().title()


def _load_tool_modules() -> dict[str, object]:
    """Import MCP tool modules lazily to avoid startup cost and cycles."""
    return {
        name: import_module(module_path)
        for name, module_path in _TOOL_MODULE_NAMES.items()
    }


def create_server() -> FastMCP:
    """Create and configure the agentgate-policy MCP server."""
    mcp = FastMCP(
        "agentgate-policy",
        instructions=(
            "AgentGate Policy Governance Kernel MCP adapter. "
            "Provides deterministic policy-governance tools for formal admissibility, "
            "proof verification, policy workflows, and scoped PII operations."
        ),
    )

    _register_tools(mcp)
    logger.info("MCP server 'agentgate-policy' initialized")
    return mcp


def _register_tools(mcp: FastMCP) -> None:
    """Register minimal policy-governance MCP tool surface."""
    modules = _load_tool_modules()

    def _register(fn, annotations: ToolAnnotations) -> None:
        mcp.tool(
            title=_titleize(fn.__name__, strip_prefix="mcp_"),
            annotations=annotations,
        )(fn)

    for module_name, attribute_name, tool_annotations in _TOOL_SPECS:
        _register(getattr(modules[module_name], attribute_name), tool_annotations)
