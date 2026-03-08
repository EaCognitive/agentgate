# Descope Credential Governance

This document defines how credentials are managed when `IDENTITY_PROVIDER_MODE=descope`
while preserving safe developer workflows for open-source and local operation.

## 1) Security Boundary

- Descope is the identity authority for user authentication and session assurance.
- AgentGate remains the authorization and policy authority for:
  - role bindings,
  - risk controls,
  - MCP authorization,
  - verification grants,
  - PII obligations.
- Production credential state must not depend on local password bootstrap.

## 2) Environment Modes

### Local OSS and Development

- `IDENTITY_PROVIDER_MODE=local`
- Local signup and password login are allowed.
- Use isolated development credentials only.

### Hybrid Migration

- `IDENTITY_PROVIDER_MODE=hybrid_migration`
- Local and provider token exchange are both accepted during migration windows.
- Use this mode only for controlled cutover validation.

### Managed Production

- `IDENTITY_PROVIDER_MODE=descope`
- Local password signup/login are disabled.
- Runtime must have valid provider settings:
  - `DESCOPE_JWKS_URL`
  - `DESCOPE_ISSUER`
  - `DESCOPE_AUDIENCE`

## 3) Credential Control for Developers

Developers can manage integration credentials without receiving production-admin capability:

- API key creation is role-constrained.
- Non-privileged roles cannot request wildcard (`*`) scope.
- Requested scopes must be within the caller role permission set.
- MCP custom scopes are limited by role policy.

Policy tuning variables:

- `API_KEY_WILDCARD_ROLES`
- `API_KEY_MCP_SCOPE_ROLES`
- `API_KEY_ALLOWED_CUSTOM_SCOPES`

Use this endpoint before provisioning keys:

- `GET /api/auth/api-keys/capabilities`

The response provides:

- normalized role,
- whether wildcard scope is allowed,
- allowed scope list,
- required scopes for MCP-admin operations.

## 4) Credential Rotation and Revocation

- Rotate Descope management keys and signing keys on defined schedule.
- Rotate API keys by creating a replacement key, validating usage, then revoking the old key.
- Use immutable audit events to record:
  - creation,
  - scope set,
  - revocation reason.

## 5) Required Production Controls

- No silent fallback from Descope to local auth.
- Fail startup if required Descope runtime configuration is missing.
- Keep `API_REFERENCE_ACCESS_MODE=admin_mcp` for hosted API explorer surfaces.
- Require role- and scope-based MCP privilege checks on sensitive operator endpoints.

## 6) Recommended Run Sequence

1. `./run gate`
2. `./run docs-check`
3. `./run cutover smoke --backend postgres-local --no-fallback`
4. Promote to staged `hybrid_migration`
5. Promote to `descope` after cutover acceptance criteria are met
