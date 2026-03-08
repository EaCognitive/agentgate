# AgentGate MCP Gold Standard

This document is the canonical MCP quality bar for AgentGate.

## Baseline

- MCP protocol: `2025-11-25`
- Python SDK: `mcp[cli]>=1.26.0,<2`
- Server identity: `agentgate-security`
- Required discovery surface:
  - `tools/list`: 48 tools
  - `resources/list`: 6 resources
  - `prompts/list`: 5 prompts

## Transport Design

- `stdio` (local AI clients): `python -m server.mcp`
- `SSE` (mounted app / local MCP clients): `/mcp/sse`
- `Streamable HTTP` (remote connectors): `/mcp` via `python -m server.mcp --http`

## Protocol Contract

- `initialize` must negotiate `protocolVersion == "2025-11-25"`.
- `initialize.capabilities` must advertise `tools`, `resources`, and `prompts`.
- `notifications/initialized` and request lifecycle are handled by FastMCP/SDK defaults.
- Tool execution errors must be returned as MCP tool results (`isError=true`), not uncaught exceptions.
- Protocol-level faults (unsupported method, malformed frame) remain JSON-RPC errors.

## Tool Schema Design Rules

- Prefer native structured arguments (`dict`/`list`) for object/array inputs.
- Preserve backward compatibility with JSON-string payloads where already shipped.
- All JSON-like parameters must fail deterministically with a structured 422-style tool error.
- Destructive operations must preserve preview/confirm token flow.

## Logging and Noise Control

- Default MCP runtime logging level: `WARNING`.
- Override with `MCP_LOG_LEVEL` when debugging (`INFO` or `DEBUG`).
- No stdout leakage before JSON-RPC frames in `stdio` mode.

## Security and Governance

- MCP calls must traverse API middleware controls (RBAC, rate limits, audit, threat detection).
- `mcp_login` is the only unauthenticated tool.
- Policy enforcement is mandatory for non-bypass operations.
- `MCP_POLICY_SET_ID` should be pinned in production for deterministic policy behavior.

## Release Gate

Run all checks before release:

```bash
uv run pytest tests/mcp_policy/test_mcp_policy_contract.py -q
uv run pytest tests/mcp_policy -q
```

A build is not release-ready if:

- `initialize` negotiates a different protocol without explicit migration updates.
- Any MCP tool path raises uncaught exceptions instead of structured tool errors.
- Discovery counts regress without intentional change documentation.
