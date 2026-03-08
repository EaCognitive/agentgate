# MCP-Privileged API Access Control

This document defines how API reference and MCP-adjacent admin surfaces are protected for
LLM-assisted operations.

## 1) Protected Surfaces

The following endpoints are treated as privileged API explorer surfaces:

- `GET /api/reference`
- `GET /openapi.json`

These endpoints are enforced by access middleware and should not be exposed as public
operator interfaces in production.

## 2) Access Mode Configuration

Set `API_REFERENCE_ACCESS_MODE`:

- `public`: no authentication gate
- `authenticated`: any authenticated user
- `admin_mcp`: role + MCP privilege checks

Default behavior:

- `staging` and `production`: `admin_mcp`
- other environments: `public`

## 3) MCP Privilege Evaluation

`admin_mcp` mode evaluates:

1. Valid bearer token
2. Active user
3. Role membership in `MCP_PRIVILEGED_ROLES` (default: `admin`)
4. Scope claim requirement for protected environments:
   - scopes configured in `MCP_REQUIRED_SCOPES`
   - enforcement toggled by `MCP_REQUIRE_SCOPE` or environment defaults

Useful endpoint for current-session evaluation:

- `GET /api/auth/mcp-access`

## 4) Dashboard Proxy Behavior

The dashboard API reference loads the backend OpenAPI document through the
dashboard proxy while preserving backend authorization checks. The backend
remains the policy source of truth.

This prevents anonymous embedding of interactive explorer data in dashboard contexts.

## 5) Developer Workflow Without Admin Escalation

Developers should use scoped API keys and capability discovery:

1. `GET /api/auth/api-keys/capabilities`
2. request explicit least-privilege scopes
3. avoid wildcard scope unless role policy allows it

This model permits integration development without granting production-level operator control.

## 6) Operational Validation

Run these checks before release:

1. Anonymous call to `/api/reference` returns `401` or `403` in protected environments.
2. Non-privileged authenticated role cannot access protected explorer endpoints.
3. MCP-privileged admin session can load `/api/reference` and `/openapi.json`.
4. Scope enforcement blocks sessions missing required MCP scope claims when enabled.
