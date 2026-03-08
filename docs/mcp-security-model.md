# MCP Security Model

This document describes the MCP runtime enforcement sequence and failure behavior.

## Enforcement Sequence

For authenticated MCP tool execution, enforcement runs in this order:

1. Authentication validation
2. Policy evaluation (`/api/policies/evaluate`)
3. Execution policy classification (`read`, `mutating`, `high_impact_mutating`)
4. Formal guardrail enforcement for mutating classes
5. Preview-confirm and MFA for high-impact operations
6. Operation execution
7. Audit event emission and evidence persistence

## Authentication

- `require_mcp_auth(validate_remote=True)` is default.
- Remote validation is cached for a short TTL (default 30 seconds).
- Invalid/expired tokens fail before tool execution.

## Policy Behavior

- `staging` and `production`: missing active policy set fails closed.
- `development` and test profiles: bypass is configurable.
- Denials are emitted as structured audit events.

## Execution Policy

Implemented in `server/mcp/execution_policy.py`.

- Every mutating operation is classified and checked before execution.
- Denials return structured payloads with operation class and reason.
- `apply_policy` and `unlock_policy` are approval-gated by guardrail policy.

## Formal MCP Path

Formal MCP tools are API-bridge only and call canonical routes:

- `POST /api/security/admissibility/evaluate`
- `POST /api/security/certificate/verify`
- `GET /api/security/evidence/chain/{chain_id}`
- `POST /api/security/delegation/issue`
- `POST /api/security/delegation/revoke`
- `POST /api/security/counterfactual/verify`

`mcp_security_evaluate_admissibility` must include top-level `runtime_solver` metadata.

## Async Job Security

Long-running operations persist status in `mcp_async_jobs` and expose status via:

- `mcp_check_job_status`
- `mcp_list_jobs`

Job failure events are tracked for operations monitoring.

## Monitoring and Notification Hooks

The MCP runtime emits counters and alerts for:

- auth validation failures
- policy-missing fail-closed events
- guardrail denials
- async job failures
- formal responses missing `runtime_solver`

These hooks are intended for dashboard/webhook/email alert channels configured via the security alert manager.

## Pre-Production Gate

Use the mandatory MCP validation gate for release readiness:

```bash
./run verify mcp policy-validation --profile staging --count 100000
```

For external report sharing, scrub artifacts first:

```bash
./run verify mcp scrub --source <artifact_dir>
```
