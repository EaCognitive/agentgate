# Descope Migration Runbook

This runbook defines the operational sequence for deploying and validating Descope-backed identity
without breaking OSS development and testing workflows.

## 1) Command Policy

All standard operational entry points must use `./run`.

- Use `./run dev` for local development.
- Use `./run demo` for full-stack Docker workflows.
- Use `./run gate` for quality verification.
- Use `./run docs-check` for hosted docs governance and bundle generation.

Direct tool commands are reserved for low-level troubleshooting only.

## 2) Environment Profiles

### Local OSS Profile

- `IDENTITY_PROVIDER_MODE=local`
- `ALLOW_LOCAL_PASSWORD_AUTH=true`
- `ALLOW_PRODUCTION_LOCAL_AUTH=false`

This profile supports local onboarding and developer iteration without external IdP dependencies.

### Migration Profile

- `IDENTITY_PROVIDER_MODE=hybrid_migration`
- `ALLOW_LOCAL_PASSWORD_AUTH=true`
- `DESCOPE_JWKS_URL=<configured>`
- `DESCOPE_ISSUER=<configured>`
- `DESCOPE_AUDIENCE=<configured>`

This profile allows parallel local and provider exchange flows for staged cutover.

### Managed Production Profile

- `IDENTITY_PROVIDER_MODE=descope`
- `ALLOW_LOCAL_PASSWORD_AUTH=false`
- `DESCOPE_JWKS_URL=<required>`
- `DESCOPE_ISSUER=<required>`
- `DESCOPE_AUDIENCE=<required>`

Local password login and signup remain disabled in this profile.

## 2.1) Reproducible Descope API Bootstrap

Use the Descope bootstrap helper to derive OIDC runtime values directly from the
project's OIDC discovery endpoint and update local env files deterministically.

Command:

```bash
./run cutover descope-setup \
  --project-id <descope_project_id> \
  --identity-mode hybrid_migration \
  --dry-run
```

Apply changes:

```bash
./run cutover descope-setup \
  --project-id <descope_project_id> \
  --identity-mode hybrid_migration
```

Optional management-key validation (reads key from environment to avoid shell history):

```bash
export DESCOPE_MANAGEMENT_KEY=<descope_management_key>
./run cutover descope-setup \
  --project-id <descope_project_id> \
  --identity-mode hybrid_migration
```

Expected outputs:

- `DESCOPE_ISSUER` from OIDC discovery `issuer`.
- `DESCOPE_JWKS_URL` from OIDC discovery `jwks_uri`.
- `DESCOPE_AUDIENCE` defaulted to project id unless overridden.
- `NEXT_PUBLIC_DESCOPE_SIGNIN_URL` and `NEXT_PUBLIC_DESCOPE_SIGNUP_URL`
  constructed from hosted flow base URL and flow ids.

Updated files:

- `.env`
- `server/.env`
- `dashboard/.env`

Failure behavior:

- OIDC discovery or JWKS failures stop the command (non-zero exit).
- Management-key validation failures also return non-zero with provider error code.
  Setup values are still computed and shown to support troubleshooting.

## 3) Pre-Cutover Validation

1. `./run gate infra`
2. `./run gate lint`
3. `./run gate test`
4. `./run docs-check`
5. `./run demo`
6. `./run status`
7. `./run cutover smoke`

Mandatory checks:

- Startup succeeds with provider runtime validation.
- `GET /api/auth/providers` returns expected mode and capabilities.
- Login/signup UI reflects provider mode restrictions.
- `POST /api/auth/exchange` returns canonical claims.

## 4) Cutover Smoke Backends (Local and Cloud)

Use `./run cutover smoke` as the canonical launcher for staged identity cutover simulation.

Backend choices:

- `sqlite`: local fallback, no Docker dependency.
- `postgres-local`: Docker `db-test` profile, representative local Postgres path.
- `postgres-cloud`: explicit external Postgres URL for staging/cloud validation.

Launch modes:

- `--launch local`: prioritize local infrastructure (`postgres-local`, optional sqlite fallback).
- `--launch cloud`: prioritize cloud path (`postgres-cloud`, then local fallback).
- `--launch auto`: infer from supplied URL and runtime environment defaults.

Cloud safety gates:

- Cloud mode requires explicit opt-in: `--allow-cloud` (or `CUTOVER_TEST_ALLOW_CLOUD=true`).
- Supply URL via `--db-url` or `CUTOVER_TEST_DATABASE_URL`.
- Default behavior avoids silent cloud execution.

Examples:

1. Local-first smoke: `./run cutover smoke --launch local`
2. Cloud staging smoke: `./run cutover smoke --launch cloud --allow-cloud --db-url <url>`
3. Force single backend: `./run cutover smoke --backend postgres-local --no-fallback`
4. Pass-through pytest filter: `./run cutover smoke -- -q`

## 5) Staged Migration Sequence

### Phase A: Hybrid Enablement

1. Deploy with `IDENTITY_PROVIDER_MODE=hybrid_migration`.
2. Validate provider token exchange for pilot tenants.
3. Confirm identity linking and role binding creation.

### Phase B: Tenant Canary

1. Restrict pilot tenant users to provider exchange.
2. Confirm PII session binding by `tenant_id`, `principal_id`, `channel_id`, and `conversation_id`.
3. Validate MCP tool operations against canonical role/permission checks.

### Phase C: Production Cutover

1. Move to `IDENTITY_PROVIDER_MODE=descope`.
2. Set `ALLOW_LOCAL_PASSWORD_AUTH=false`.
3. Validate high-risk verification paths require grants and assurance.

## 6) Verification and Security Gates

For counterfactual verification in staging/production:

- `verification_grant_token` is required.
- High-risk tiers (`R3`, `R4`) require elevated roles and assurance checks.
- Policy decisions are persisted for auditability.

For MCP flows:

- `mcp_counterfactual_verify` routes through secured API verification endpoint.
- Formal/delegation tools use explicit permission mapping.

For API explorer surfaces:

- set `API_REFERENCE_ACCESS_MODE=admin_mcp` in staging/production,
- ensure `MCP_PRIVILEGED_ROLES` and `MCP_REQUIRED_SCOPES` match your role/claim policy,
- validate session entitlement with `GET /api/auth/mcp-access`.

## 7) Rollback and Degraded Operation

If provider validation fails:

1. Move to `IDENTITY_PROVIDER_MODE=hybrid_migration`.
2. Keep local auth enabled only as temporary fallback in non-production.
3. Revalidate JWKS/issuer/audience configuration before reattempting full cutover.

Production policy:

- No silent fallback to local mode.
- Any emergency override must be explicit and auditable.

## 8) OSS Compatibility Checklist

- `local` mode remains first-class and fully testable.
- `custom_oidc` adapter remains supported via common interface contract.
- Business services must remain provider-agnostic.
- Documentation and examples must not assume Descope-only deployment.

## 9) Release Exit Criteria

- `./run gate` passes.
- `./run docs-check` passes.
- Dashboard build and runtime are healthy.
- Verification-control tests pass for API and MCP formal paths.
- Docs binder navigation and classification include all new docs pages.
