# Runtime Enforcement and SDK Alignment

Last updated: 2026-02-12

## Scope
This document defines the runtime truth for two claims:

1. Runtime Z3-backed admissibility enforcement.
2. Permission-aware bidirectional PII restoration in the SDK.

The intent is to make runtime behavior and test evidence explicit, not inferred from unit-only proofs.

## Runtime Z3 Enforcement

### Mode control
Runtime solver mode is controlled by `AGENTGATE_Z3_MODE` in
`/Users/macbook/Desktop/agentgate/server/policy_governance/kernel/solver_engine.py`.

Supported values:
- `off`: Python predicate path only.
- `shadow`: Python + Z3 dual-run, drift treated as security failure.
- `enforce`: Z3 result is authoritative.

Production safety policy:
- `off` is restricted to local/dev/test runtimes.
- invalid mode values fail startup in non-local runtimes.

### Fail-closed behavior
- In `shadow`: solver drift or Z3 evaluation error sets decision to inadmissible.
- In `enforce`: Z3 evaluation error sets decision to inadmissible.

### Runtime evidence payload
Decision certificates include:
- `proof_payload.runtime_solver.solver_mode`
- `proof_payload.runtime_solver.solver_backend`
- `proof_payload.runtime_solver.z3_check_result`
- `proof_payload.runtime_solver.drift_detected`
- `proof_payload.runtime_solver.failure_reason` (when present)

The Z3 theorem checks are implemented in
`/Users/macbook/Desktop/agentgate/server/policy_governance/kernel/z3_runtime_engine.py`
and call `Solver.check()` for base, theorem, and negated theorem satisfiability checks.

## SDK -> API -> Kernel path

### Canonical request path
1. SDK helper:
   `/Users/macbook/Desktop/agentgate/ea_agentgate/api_client.py`
   `DashboardClient.formal_evaluate_admissibility()`
2. API route:
   `/Users/macbook/Desktop/agentgate/server/routers/policy_governance.py`
   `POST /api/security/admissibility/evaluate`
3. Enforcement entrypoint:
   `/Users/macbook/Desktop/agentgate/server/policy_governance/kernel/enforcement.py`
   `enforce_action()`
4. Kernel evaluator:
   `/Users/macbook/Desktop/agentgate/server/policy_governance/kernel/solver_engine.py`
   `evaluate_admissibility()`
5. Runtime Z3 evaluator:
   `/Users/macbook/Desktop/agentgate/server/policy_governance/kernel/z3_runtime_engine.py`
   `check_admissibility_z3()`

This is the path exercised by the SDK end-to-end runtime test listed below.

SDK formal middleware provider defaults:
- `verification_provider="remote"` is the production-facing default.
- `verification_provider="local"` remains available for explicit offline testing.

## Permission-aware Bidirectional PII

### Runtime behavior
Automatic bidirectional PII transformation is active only when SDK middleware is configured with:
- `PIIVault(use_server_api=True, ...)`
- A valid scoped `session_id`
- Valid auth token with required server permissions

Server permission checks are authoritative:
- Redact requires `PII_STORE`
- Restore requires `PII_RETRIEVE`

### SDK wiring
- Middleware implementation:
  `/Users/macbook/Desktop/agentgate/ea_agentgate/middleware/pii_vault.py`
- Middleware override support:
  `/Users/macbook/Desktop/agentgate/ea_agentgate/middleware/base.py`
  (`ctx.metadata["result_override"]`)
- LLM path integration:
  `/Users/macbook/Desktop/agentgate/ea_agentgate/integrations/openai.py`
  `/Users/macbook/Desktop/agentgate/ea_agentgate/integrations/anthropic.py`

If restore is unauthorized and `fail_closed=True`, SDK call fails with an explicit error.

## MCP Tool Alignment

`/Users/macbook/Desktop/agentgate/server/adapters/mcp_policy/tools_policy_governance.py`
`mcp_security_evaluate_admissibility()` now returns:
- `certificate`
- `runtime_solver` (extracted from certificate proof payload)

This makes runtime backend metadata directly available to MCP clients without certificate parsing.

## Verification Evidence

### Runtime Z3 unit tests
- `/Users/macbook/Desktop/agentgate/tests/security/test_verification_controls.py`

### MCP formal tool tests
- `/Users/macbook/Desktop/agentgate/tests/mcp_policy/test_mcp_policy_contract.py`
- `/Users/macbook/Desktop/agentgate/tests/mcp_policy/test_mcp_policy_auth_guardrails.py`

### SDK real-path end-to-end tests
- `/Users/macbook/Desktop/agentgate/tests/e2e/test_formal_pii_sdk_journey.py`
- `/Users/macbook/Desktop/agentgate/tests/main_tests/test_lifecycle.py`

### Mandatory pre-production gate
- `/Users/macbook/Desktop/agentgate/.github/workflows/ci.yml`
  `pre-production-enforcement-gate`
- Gate runtime profile:
  - `AGENTGATE_Z3_MODE=enforce`
  - `AGENTGATE_FORCE_REMOTE_VERIFICATION=true`
  - `IDENTITY_PROVIDER_MODE=hybrid_migration`
- This gate blocks CI status if runtime enforcement journey checks fail.

### Scheduled chaos campaign profiles
- `/Users/macbook/Desktop/agentgate/.github/workflows/formal-chaos-campaign.yml`
- Campaign scale is selected by `CHAOS_COMPLIANCE_PROFILE`
  (`development|soc2|soc3|hipaa|regulated`) and can be overridden with
  `CHAOS_ITERATIONS` and `CHAOS_WORKERS`.
- Identity profile compatibility is enforced using
  `CHAOS_IDENTITY_PROFILE` / `IDENTITY_PROVIDER_MODE`.
- Default scheduled profile is `soc2` + `hybrid_migration`; dispatch can use stricter profiles.
- Fail-fast violations write `FAIL_FAST_TRACE.json` in the run artifact directory and
  are uploaded even on workflow failure.

### Forensic formal runtime run (live route path)
- Command: `./run verify formal run --count <n> --workers <n> --enforce-runtime`
- This run executes canonical server routes at scale:
  `POST /api/security/admissibility/evaluate` ->
  `POST /api/security/certificate/verify` ->
  `GET /api/security/evidence/chain/{chain_id}`.
- Artifacts are written to:
  `tests/artifacts/formal_runtime_forensic_run_*`
  with report, per-transition ledger, and summary hashes.
- Output is privacy-safe by default:
  token-like values and email patterns are redacted in persisted traces.
- Pre-share scrub gate:
  `./run verify formal scrub` produces sanitized share bundles in
  `tests/artifacts/share/` and fails closed on residual sensitive patterns.

## Distributed Health Monitoring and Notifications

### Runtime monitor
- Module:
  `/Users/macbook/Desktop/agentgate/server/policy_governance/kernel/distributed_health_monitor.py`
- Lifecycle wiring:
  `/Users/macbook/Desktop/agentgate/server/lifespan.py`
- Health status endpoints:
  `GET /api/health` and `GET /api/health/distributed`

### Alert channels
- Runtime alert manager factory:
  `/Users/macbook/Desktop/agentgate/server/policy_governance/kernel/alerting_factory.py`
- Threat detection and health monitor alerts can route to:
  - structured logs
  - webhook
  - Slack webhook
- Configure channels and thresholds via:
  `SECURITY_ALERT_*` environment variables in `.env.example` and `server/.env.example`.

The e2e suite validates:
- SDK formal helper reaches kernel certificate with runtime Z3 metadata.
- Agent formal middleware uses remote canonical endpoint path when remote mode is forced in non-production test runtime.
- Scoped PII redaction/restore round-trip on authorized path.
- Fail-closed behavior when restore permission is denied.
- Startup fails when `AGENTGATE_Z3_MODE=off` is configured in production runtime.
