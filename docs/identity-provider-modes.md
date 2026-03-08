# Identity Provider Modes and Descope Integration

This document defines how authentication is integrated with the AgentGate policy plane.

## Scope and Ownership

- Descope, Local, or Custom OIDC handles identity proofing and token/session issuance.
- AgentGate remains the source of truth for:
  - role bindings,
  - risk profiles,
  - MCP tool authorization,
  - PII obligations and channel binding,
  - verification grants and formal-control gates.

## Provider Modes

Set `IDENTITY_PROVIDER_MODE` in runtime configuration:

- `local`: Local username/password sign-in and signup are enabled.
- `descope`: External provider token exchange is required; local password auth is disabled unless explicitly overridden.
- `custom_oidc`: Generic OIDC token exchange is required.
- `hybrid_migration`: Local + provider token exchange are both allowed for migration windows.

## Required Environment Variables

### Shared

- `IDENTITY_PROVIDER_MODE` (`local|descope|custom_oidc|hybrid_migration`)
- `ALLOW_LOCAL_PASSWORD_AUTH` (`true|false`, only used outside pure local mode)
- `ROLE_OPERATOR_ALIAS_ENABLED` (`true|false`, compatibility alias for `operator -> approver`)
- `API_REFERENCE_ACCESS_MODE` (`public|authenticated|admin_mcp`)
- `MCP_PRIVILEGED_ROLES` (CSV role list for MCP-privileged endpoints)
- `MCP_REQUIRED_SCOPES` (CSV scope list when scope enforcement is active)
- `MCP_REQUIRE_SCOPE` (`true|false`, overrides environment default)

### Descope Mode

- `DESCOPE_JWKS_URL` (required in production)
- `DESCOPE_ISSUER` (recommended)
- `DESCOPE_AUDIENCE` (recommended)

### Custom OIDC Mode

- `OIDC_JWKS_URL` (required in production)
- `OIDC_ISSUER` (recommended)
- `OIDC_AUDIENCE` (recommended)

### Production Safety Override

- `ALLOW_PRODUCTION_LOCAL_AUTH=true` is required to run `IDENTITY_PROVIDER_MODE=local` in production.

If the override is not set, startup fails fast.

## Dashboard Redirect Variables

Configure dashboard redirect targets for provider onboarding:

- `NEXT_PUBLIC_DESCOPE_SIGNIN_URL`
- `NEXT_PUBLIC_DESCOPE_SIGNUP_URL`

The dashboard login/signup pages use these values when provider mode is not local.

## Canonical Auth Flow

1. Identity provider issues token.
2. Client calls `POST /api/auth/exchange` with `provider_token`.
3. AgentGate validates token via the selected provider adapter.
4. AgentGate resolves/creates:
   - user record,
   - principal link,
   - tenant role binding,
   - baseline risk profile.
5. AgentGate returns canonical session tokens with enriched claims:
   - `roles`,
   - `provider`,
   - `provider_subject`,
   - `tenant_id`,
   - `session_assurance`,
   - `principal_risk`.

## Role Canonicalization

Canonical roles:

- `admin`
- `security_admin`
- `approver`
- `auditor`
- `developer`
- `agent_operator`
- `service_agent`
- `viewer`

Legacy alias:

- `operator` maps to `approver` while `ROLE_OPERATOR_ALIAS_ENABLED=true`.
- Disable alias enforcement by setting `ROLE_OPERATOR_ALIAS_ENABLED=false`.

## Risk and Verification Controls

Counterfactual verification (`POST /api/security/counterfactual/verify`) enforces:

- session assurance from JWT claims,
- risk-tier to canonical risk mapping,
- high-risk role restrictions (`admin|security_admin|approver` for `R3/R4`),
- tenant resource scope checks,
- verification grant requirement in staging/production and high-risk paths,
- immutable policy decision recording.

Verification grants:

- issued by `POST /api/verification/authorize`,
- consumed by `POST /api/verification/consume` or directly by formal verification paths,
- single-use and time-bounded,
- tenant/principal/session-assurance constrained.

## PII Session Binding

PII sessions now bind operations by:

- `tenant_id`,
- `principal_id`,
- `channel_id`,
- `conversation_id`,
- `agent_id`,
- `authorized_viewers`.

Redaction and restoration enforce these bindings at request time using scoped headers.

## OSS and BYO Auth Compatibility

Open-source deployments can stay on `local` mode without Descope.

For custom providers:

- implement an `IdentityProviderAdapter`,
- validate token signatures against trusted JWKS,
- map claims into canonical fields (`sub`, email, tenant, roles, assurance),
- pass provider contract tests before production enablement.

## API Explorer and MCP-Privileged Endpoints

- `GET /api/reference` and `GET /openapi.json` are controlled by
  `API_REFERENCE_ACCESS_MODE`.
- In `admin_mcp` mode, access requires:
  - role membership in `MCP_PRIVILEGED_ROLES`,
  - required scope claim match (`MCP_REQUIRED_SCOPES`) when scope enforcement is active.
- Use `GET /api/auth/mcp-access` to validate current-session privilege evaluation.

## Migration Runbook (Local -> Provider)

1. Set `IDENTITY_PROVIDER_MODE=hybrid_migration`.
2. Enable provider token exchange and validate claims in staging.
3. Backfill identity links and role bindings.
4. Cut over tenants to provider login.
5. Switch mode to `descope` or `custom_oidc`.
6. Disable local password auth in production.

No silent fallback from provider mode to local mode is allowed in production.
