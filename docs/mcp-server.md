# AgentGate MCP Server (Authenticated API Bridge)

AgentGate MCP is the authenticated tool and resource bridge into the main REST
API. Use this guide for the route model, local startup path, and operator
access expectations.

Protocol baseline for this repository:
- MCP protocol: `2025-11-25`
- Python SDK: `mcp[cli]>=1.26.0,<2`

## 1) Architecture

AgentGate MCP is an authenticated bridge, not a DB client.

Flow:
- User -> LLM -> MCP tool/resource -> `MCPApiClient` -> REST API -> API middleware (RBAC, audit, rate limits, threat detection) -> DB/runtime

This guarantees MCP traffic goes through the same security controls as dashboard/API traffic.

### Policy-Governance Validation Path

Runtime MCP validation is executed by:

- `scripts/validate_policy_governance_adapter.py` (live transport validator)
- `./run verify mcp policy-validation --profile <dev|staging|prod-like> --count <N>`

Artifact outputs are written to:

- `tests/artifacts/algorithm/policy_governance_validation/`

Scrubbing before external sharing is required:

- `./run verify mcp scrub --source <artifact_dir>`

## 1.1) Docs Route Model

Docs and API reference are intentionally split:
- Dashboard docs UX: `/docs`
- Dashboard API reference: `/docs/api-reference`
- Backend raw Scalar endpoint: `/api/reference`
- OpenAPI JSON source: `/openapi.json`

This keeps the public docs experience in the dashboard and reserves the backend
reference route for raw, direct access.

## 2) Authentication Model

All retained MCP tools require authentication except `mcp_login`.

Supported session/auth tools:

- `mcp_login`
- `mcp_logout`
- `mcp_whoami`

### 2.1) Runtime Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `MCP_API_URL` | API server URL (default: `http://localhost:8000`) | No |
| `AGENTGATE_URL` | Alias for `MCP_API_URL` | No |
| `MCP_AUTH_TOKEN` | Pre-authenticated JWT token | No |
| `MCP_EMAIL` | Email for login workflows | No |
| `MCP_PASSWORD` | Password for login workflows | No |
| `MCP_POLICY_SET_ID` | Policy set pin for MCP enforcement | No |
| `MCP_STDIO_TRUSTED` | Enable trusted stdio transport context | No |
| `MCP_LOG_LEVEL` | Logging level (default: `WARNING`) | No |
| `PRESIDIO_LOG_LEVEL` | NLP detector logging level | No |

### 2.2) Default Development Credentials

For local development only:

- Email: `admin@admin.com`
- Password: `password`

## 2.7) First-Time Setup

New installations require a secure initialization sequence:

```bash
./run demo
curl http://localhost:8000/api/setup/status
curl -X POST http://localhost:8000/api/setup/complete \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"SecurePassword123!@#","generate_api_key":true}'
```

Setup returns an API key for MCP authentication and configures the initial admin account.

### Reset for First-Run Validation (Development Only)

Use this procedure only in non-production environments when you need to re-test onboarding from an empty system state:

```bash
docker compose down --volumes --remove-orphans
docker compose up -d --build
curl http://127.0.0.1:8000/api/setup/status
curl http://127.0.0.1:3000/api/setup/status
```

Expected result on both endpoints:
- `setup_required: true`
- `user_count: 0`

Production guidance:
- Do not run volume-destructive reset commands in production.
- Setup completion is accepted only during the initial setup window and requires an empty users table.

## 2.8) Master Security Key

Protected operations require the Master Security Key file (`~/.ea-agentgate/master.key`):

| Operation | Description |
|-----------|-------------|
| `delete_all_users` | Remove all user accounts |
| `drop_database_tables` | Schema destruction |
| `disable_security_middleware` | Disable threat detection |
| `export_all_pii` | Bulk PII export |
| `factory_reset` | Complete system reset |

Generate the key file during setup:

```bash
curl -X POST http://localhost:8000/api/security/master-key/key-file/generate \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"passphrase":"<16+ char passphrase>","passphrase_confirm":"<same>"}'
```

Unlock for protected operations:

```bash
curl -X POST http://localhost:8000/api/security/master-key/key-file/unlock \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"passphrase":"<passphrase>","operation":"<op>","reason":"<reason>"}'
```

The key file is AES-256-GCM encrypted. Backup codes are generated at creation time for recovery.

## 3) Router Wiring (Required)

Required mount behavior:
- Policies router normalized to `APIRouter(prefix="/policies")` and mounted under `/api` => `/api/policies/*`
- PII compliance router mounted under `/api/pii` => `/api/pii/compliance-checklist`

## 4) Tool Surface

Retained minimal MCP policy adapter surface:

- Session/auth:
  - `mcp_login`
  - `mcp_logout`
  - `mcp_whoami`
- Policy governance core:
  - `mcp_security_evaluate_admissibility`
  - `mcp_security_verify_certificate`
  - `mcp_evidence_verify_chain`
  - `mcp_counterfactual_verify`
  - `parse_nl_policy`
  - `simulate_policy`
  - `apply_policy`
  - `unlock_policy`
- PII core:
  - `mcp_pii_session_create`
  - `mcp_pii_redact`
  - `mcp_pii_restore`
  - `mcp_pii_session_clear`
- Runtime introspection:
  - `mcp_guardrails_status`
  - `mcp_check_job_status`
  - `mcp_list_jobs`

## 5) One-Liner Setup

### 5.1 Local API (Docker)

```bash
./run demo
```

Canonical entry point is `./run`. Use raw `docker compose` commands only for low-level troubleshooting.

Health check:

```bash
curl -fsS http://127.0.0.1:8000/api/health
```

Quick docs route check:

```bash
curl -I http://127.0.0.1:8000/api/reference
curl -I http://127.0.0.1:8000/openapi.json
```

### 5.2 MCP Server (stdio)

```bash
MCP_API_URL=http://127.0.0.1:8000 MCP_STDIO_TRUSTED=true MCP_LOG_LEVEL=WARNING uv run --extra server python -m server.mcp
```

### 5.3 Claude Code one-liner (stdio)

```bash
claude mcp add --transport stdio agentgate -- env MCP_API_URL=http://127.0.0.1:8000 MCP_STDIO_TRUSTED=true MCP_LOG_LEVEL=WARNING uv run --extra server python -m server.mcp
```

Verify:

```bash
claude mcp list
```

### 5.4 Policy-Governance Validation

```bash
./run verify mcp policy-validation --profile dev --count 10000
./run verify mcp latest
./run verify mcp scrub --source tests/artifacts/algorithm/policy_governance_validation/<run_id>
```

### 5.3.1 Dashboard + API + Proxy (local production-like stack)

```bash
./run demo
```

Then verify docs routing:

```bash
curl -I https://<your-domain>/docs
curl -I https://<your-domain>/api
curl -I https://<your-domain>/api/reference
curl -I https://<your-domain>/openapi.json
curl -I https://<your-domain>/static/vendor/scalar-api-reference-1.44.13.min.js
```

### 5.4 OpenAI Responses API one-liner (remote MCP tool)

Run MCP over HTTP first:

```bash
MCP_API_URL=http://127.0.0.1:8000 MCP_STDIO_TRUSTED=true MCP_LOG_LEVEL=WARNING uv run --extra server python -m server.mcp --http --port 8102
```

Then call OpenAI Responses with MCP tool:

```bash
curl https://api.openai.com/v1/responses \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{
    "model": "gpt-5",
    "tools": [{
      "type": "mcp",
      "server_label": "agentgate",
      "server_url": "https://<public-agentgate-mcp-url>/mcp",
      "require_approval": "always"
    }],
    "input": "Call mcp_whoami and summarize the authenticated user."
  }'
```

Notes:
- `server_url` must be publicly reachable by OpenAI. `localhost` will not work unless tunneled.
- If your MCP server requires OAuth upstream auth, pass `authorization` in the MCP tool definition.

## 6) Policy Enforcement Guidance

Default behavior:
- If `MCP_POLICY_SET_ID` is set, that exact policy is enforced.
- If not set, MCP selects a loaded DB-backed policy for evaluation.

Recommended production practice:
- Pin policy explicitly with `MCP_POLICY_SET_ID` to avoid ambiguous multi-policy environments.

## 7) Preview/Confirm Safety

Destructive tools (`block_ip_temp`, `create_incident`, `revoke_token`, `apply_policy`, `unlock_policy`, etc.) require:
1. Preview call (`confirm=false`)
2. Signed `preview_token`
3. Confirm call (`confirm=true`, matching token)

Token protections:
- HMAC signed
- TTL bounded
- Parameter bound

## 8) Verification (Automated + Manual)

### 8.1 Automated

```bash
uv run pytest tests/mcp_policy -q
uv run pytest tests/mcp_policy/test_mcp_policy_contract.py -q
```

### 8.2 Full manual MCP traversal (all tools/resources/prompts)

This repository includes a full MCP E2E verifier:
- `scripts/verify_mcp_e2e.py`

Host-run exhaustive pass (pins allow policy):

```bash
MCP_POLICY_SET_ID=<allow-policy-id> uv run python scripts/verify_mcp_e2e.py --base-url http://127.0.0.1:8000
```

Container-run exhaustive pass (MCP process launched inside Docker):

```bash
docker cp scripts/verify_mcp_e2e.py agentgate-server-1:/tmp/verify_mcp_e2e.py
docker compose exec -T -e MCP_POLICY_SET_ID=<allow-policy-id> server python3 /tmp/verify_mcp_e2e.py --base-url http://127.0.0.1:8000
```

To create a dedicated allow policy ID for pinning, call `mcp_policies_create` with a policy whose `default_effect` is `allow` and empty `rules`.

Both commands verify:
- tool inventory + resource inventory + prompt inventory
- unauthenticated rejection before login
- login/whoami/logout lifecycle
- read + write + update + delete + revert flows
- destructive preview/confirm flows
- policy tool behavior
- dataset run/export flow
- PII detect/redact/stats/compliance

### 8.3 Explicit policy-deny enforcement test

```bash
# 1) create deny policy under allow pin
# 2) run with MCP_POLICY_SET_ID=<deny-policy-id>
# 3) call mcp_users_create and assert 403 Policy denied
```

(Use the same MCP client path as above; this is enforced in both host and Docker execution paths.)

### 8.4 Inspector smoke

```bash
npx @modelcontextprotocol/inspector uv run python -m server.mcp
```

## 9) Docker Runtime Notes

The server image installs spaCy models at build time (`en_core_web_lg`, `xx_ent_wiki_sm`).
Runtime checks:
- `GET /api/pii/nlp/status` should show loaded engines
- `POST /api/pii/detect` should return detections
- `GET /api/pii/compliance-checklist` should resolve

If you want low-noise logs, set:

```bash
PRESIDIO_LOG_LEVEL=ERROR
```

## 10) Troubleshooting

- `401 MCP client not authenticated`
  - Call `mcp_login`, or start MCP with `MCP_AUTH_TOKEN`
- `403` on tools after login
  - API RBAC or MCP policy denied the operation
- `/api/policies` 404
  - Router prefix/mount mismatch (`/policies` + app `/api`)
- `/api/pii/compliance-checklist` 404
  - Missing `pii_compliance_router` mount at `/api/pii`
- OpenAI MCP tool cannot connect
  - `server_url` is not publicly reachable or not using supported MCP HTTP transport
- `/docs` shows backend Scalar instead of dashboard
  - nginx route ownership is wrong; `/docs` must route to dashboard backend
- `/docs/api-reference` renders blank or missing API data
  - verify the dashboard API reference can still load the backend OpenAPI document
- Scalar JS 404 at `/static/vendor/scalar-api-reference-1.44.13.min.js`
  - ensure nginx routes `/static/vendor/*` to API backend, not dashboard static proxy
- Docker server restart loop on startup (`UndefinedColumnError` / missing columns)
  - database schema is behind application models
  - run migrations before start, or recreate local dev volumes for a fresh schema

## 11) External References

- OpenAI Docs MCP quickstart (Codex MCP setup):
  - https://platform.openai.com/docs/docs-mcp
- OpenAI Codex MCP configuration:
  - https://developers.openai.com/codex/mcp/
- OpenAI Responses API with remote MCP tools, approvals, and `require_approval`:
  - https://platform.openai.com/docs/guides/tools-connectors-mcp
- Anthropic Claude Code MCP command reference (`claude mcp add`, `claude mcp list`):
  - https://docs.anthropic.com/en/docs/claude-code/mcp
