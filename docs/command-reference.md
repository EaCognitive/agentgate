# AgentGate Command Reference

This document is the canonical command handbook for local development, quality gates, operations, and deployment orchestration.

## 1) Command Policy

- Canonical entry point: `./run`
- Compatibility wrappers: `make <target>` (delegates to `./run` for core workflows)
- Direct low-level commands (`docker compose`, `pytest`, `ea-agentgate`) are allowed for troubleshooting and advanced use only.

## 2) Primary Entry Commands (`./run`)

| Command | Purpose | Destructive |
|---|---|---|
| `./run demo [--fresh]` | Start the Docker stack with the production dashboard runtime, run health checks, and open the dashboard | No |
| `./run dev` | Start backend (`uvicorn --reload`) and dashboard (`next dev`) for hot-reload development | No |
| `./run gate` | Run chronological quality gate (`infra -> lint -> test`) | No |
| `./run gate infra` | Run infrastructure and secrets audit only | No |
| `./run gate lint` | Run lint/build phase only | No |
| `./run gate test` | Run tests phase only | No |
| `./run test [args...]` | Run test suite through `./test` wrapper | No |
| `./run cutover smoke [options]` | Run identity cutover simulation (`hybrid_migration -> descope`) with backend fallback | No |
| `./run cutover descope-setup [options]` | Resolve Descope OIDC settings and write reproducible env configuration | No |
| `./run verify formal [latest|json|history|path|run|scrub|organize|report]` | Read canonical verification artifacts, execute formal runtime campaign, scrub/organize share artifacts, or generate report package | No |
| `./run verify mcp [policy-validation|latest|history|scrub]` | Execute MCP policy-governance validation, inspect MCP artifacts, or scrub artifact exports | No |
| `./run lint` | Run Ruff + Pylint + dashboard production build | No |
| `./run docs-check` | Build docs bundle and run strict docs governance checks | No |
| `./run status` | Show service/port health status | No |
| `./run logs [service...]` | Tail Docker logs | No |
| `./run stop` | Stop containers while preserving volumes/data | No |
| `./run clean` | Remove containers and caches; preserve volumes | No |
| `./run clean --wipe-data` | Remove containers, caches, and volumes (full reset) | Yes |
| `./run seed` | Open browser onboarding (`/setup`) | No |
| `./run ops <ea-agentgate-command>` | Execute the `ea-agentgate` CLI via the canonical entry path | No |
| `./run help` | Show command menu and usage | No |

## 3) Chronological Quality Gate

`./run gate` executes a deterministic three-phase sequence:

1. Phase 1: Infrastructure and secrets audit
2. Phase 2: Style and structure checks (`ruff`, `pylint`, dashboard build)
3. Phase 3: Test execution (`./test --no-open`)

Use phase-specific commands to isolate failures:

- `./run gate infra`
- `./run gate lint`
- `./run gate test`

## 3.1) Zero-State Startup

Use `./run demo --fresh` for deterministic first-pull startup or any full
local re-initialization.

`--fresh` behavior:

- Executes `docker compose down -v --remove-orphans` before startup.
- Removes persisted local PostgreSQL/Redis/server state volumes for this project.
- Rebuilds and starts the stack from a clean state.

Use `./run demo` (without `--fresh`) when intentionally preserving local data.

Runtime mode policy:

- `./run demo` is the portfolio and validation path. It serves the same
  production Next runtime that should back `localhost:3000`.
- `./run dev` is the developer path. It uses hot reload and may not match the
  production dashboard byte-for-byte.

Startup safety behavior:

- `./run demo` records container lifecycle events before and after orchestration.
- Events are written to:
  - `tests/artifacts/operations/container_lifecycle/events.jsonl`
  - `tests/artifacts/operations/container_lifecycle/latest.json`
- Each event includes run ID, timestamp, container IDs, health states, ports, and project volumes.

## 4) Test Runner (`./run test` / `./test`)

`./run test` delegates to `./test`, which supports pass-through `pytest` args and runner flags.

Runner flags:

- `--no-parallel`
- `--workers N`
- `--no-open`
- `--no-clean`
- `--report`
- `--serve`
- `--clean`
- `--help-test`

Examples:

- `./run test`
- `./run test --no-open`
- `./run test --workers 4 -k pii`
- `./run test tests/security -q`

## 5) Cutover Smoke Command (`./run cutover smoke`)

Canonical smoke target:

- `tests/integration/test_identity_cutover.py`

Default behavior (`auto`):

- Chooses backend by launch/environment context.
- Tries PostgreSQL path first.
- Falls back to SQLite in non-production contexts unless disabled.

Options:

- `--backend auto|sqlite|postgres-local|postgres-cloud`
- `--launch auto|local|cloud`
- `--db-url <postgresql-url>`
- `--allow-cloud` (required for `postgres-cloud` backend)
- `--no-fallback`
- `-- ...` (pass-through pytest args)

Examples:

- `./run cutover smoke`
- `./run cutover smoke --backend postgres-local`
- `./run cutover smoke --backend postgres-cloud --db-url <url> --allow-cloud`
- `./run cutover smoke --launch cloud --allow-cloud --db-url <url>`

Important:

- `cutover smoke` validates integration behavior and does not launch the dashboard stack.
- Use `./run demo` or `./run demo --fresh` to run interactive setup/login UX.

## 5.1) Descope Setup Helper (`./run cutover descope-setup`)

Use this command to derive provider runtime values from Descope OIDC discovery and
update local env files in a deterministic way.

Options:

- `--project-id <descope-project-id>` (required)
- `--identity-mode local|hybrid_migration|descope|custom_oidc`
- `--management-key-env <env-var-name>` (default: `DESCOPE_MANAGEMENT_KEY`)
- `--management-key <raw-key>` (optional; avoid in shared shell history)
- `--audience <value>` (defaults to project id)
- `--signin-flow-id <flow-id>` (default: `sign-up-or-in`)
- `--signup-flow-id <flow-id>` (default: `sign-up-or-in`)
- `--dry-run`
- `--json`

Examples:

- `./run cutover descope-setup --project-id <id> --dry-run`
- `DESCOPE_MANAGEMENT_KEY=<key> ./run cutover descope-setup --project-id <id>`

Environment variables:

- `CUTOVER_SMOKE_BACKEND`
- `CUTOVER_SMOKE_LAUNCH`
- `CUTOVER_TEST_DATABASE_URL`
- `CUTOVER_TEST_ALLOW_CLOUD`
- `CUTOVER_ALLOW_SQLITE_FALLBACK`

Safety defaults:

- Cloud backend is blocked unless explicitly enabled (`--allow-cloud` or `CUTOVER_TEST_ALLOW_CLOUD=true`).
- Production/staging defaults disable SQLite fallback unless `CUTOVER_ALLOW_SQLITE_FALLBACK=true`.

## 6) Operations CLI via Canonical Entry

Use `./run ops` instead of invoking `ea-agentgate` directly.

Examples:

- `./run ops login`
- `./run ops whoami`
- `./run ops overview --json`
- `./run ops threats list --json`
- `./run ops pii detect "Contact me at user@example.com"`
- `./run ops pii redact --session-id session_abc123 "SSN 123-45-6789"`
- `./run ops approvals pending`

For full command tree:

- `./run ops --help`
- `./run ops <subcommand> --help`

## 7) Verification Artifacts Policy

Canonical verification source:

- `tests/artifacts/algorithm/formal_verification/latest/` is the single source of truth for latest verification-grade results.
- `tests/artifacts/algorithm/formal_verification/history/` stores previous canonical snapshots.
- Quick profiles (for example `10k`) do not publish into `latest/`.

Commands:

- `./run verify formal latest` - show canonical latest summary
- `./run verify formal json` - print canonical latest JSON results
- `./run verify formal history` - list archived canonical snapshots
- `./run verify formal path` - print canonical latest directory path
- `./run verify formal run [options]` - execute forensic runtime journey via live API routes and write evidence artifacts
- `./run verify formal scrub [options]` - create a scrubbed share bundle and verify no sensitive patterns remain
- `./run verify formal organize [--execute]` - normalize legacy artifact directories into canonical layout
- `./run verify formal report [options]` - generate policy-governance verification report package (Markdown + optional PDF + manifest)
- `./run verify mcp policy-validation [options]` - run live MCP validation against canonical API paths and write forensic artifacts
- `./run verify mcp latest` - print latest MCP validation summary
- `./run verify mcp history` - list MCP validation artifact directories
- `./run verify mcp scrub --source <artifact_dir>` - scrub and verify MCP artifact content for safe sharing

Formal forensic run options:

- `--count <n|nk>` transition count (for example `50k`, `100k`, `500k`)
- `--workers <n>`
- `--compliance-profile development|soc2|soc3|hipaa|regulated`
- `--identity-profile local|hybrid_migration|descope|custom_oidc`
- `--verify-every <n>` route-level certificate/evidence verification frequency
- `--enforce-runtime` require `solver_mode=enforce` and `solver_backend=z3`
- `--no-fail-fast` keep collecting failures (default is fail fast)
- `--skip-chaos` skip kernel chaos stage and run live route stage only

Forensic outputs:

- `tests/artifacts/algorithm/formal_verification/runs/formal_runtime_forensic_run_*/formal_runtime_forensic_report.json`
- `tests/artifacts/algorithm/formal_verification/runs/formal_runtime_forensic_run_*/formal_runtime_forensic_ledger.jsonl`
- `tests/artifacts/algorithm/formal_verification/runs/formal_runtime_forensic_run_*/SUMMARY.txt`
- `tests/artifacts/algorithm/formal_verification/runs/formal_runtime_forensic_run_*/FAIL_FAST_TRACE.json` (on failure)
- `tests/artifacts/algorithm/formal_verification/latest_forensic/` (latest snapshot)
- `tests/artifacts/algorithm/formal_verification/history_forensic/` (prior latest snapshots)

Formal share scrub options:

- `--source-profile latest-forensic|latest-canonical` source selection when no explicit source is provided
- `--source-dir <path>` explicit source directory to scrub or verify
- `--output-dir <path>` explicit scrubbed output directory
- `--verify-only` scan source content for sensitive patterns without writing output
- `--overwrite` replace existing output directory

Formal share scrub outputs:

- `tests/artifacts/share/*/SCRUB_REPORT.json`
- `tests/artifacts/share/*/MANIFEST.json`
- `tests/artifacts/share/*/SHARE_SUMMARY.txt`

Formal report options:

- `--source-profile latest-forensic|latest-canonical` source selection when no explicit source directory is provided
- `--source-dir <path>` explicit forensic artifact directory
- `--output-dir <path>` explicit report package output directory
- `--format markdown|pdf|both` output format selection
- `--strict-pdf` fail if PDF toolchain is unavailable when PDF output is requested
- `--title <text>` custom report title

Formal report outputs:

- `tests/artifacts/reports/*/POLICY_GOVERNANCE_VERIFICATION_REPORT.md`
- `tests/artifacts/reports/*/POLICY_GOVERNANCE_VERIFICATION_REPORT.pdf` (if generated)
- `tests/artifacts/reports/*/REPORT_MANIFEST.json`

Artifact organization outputs:

- `tests/artifacts/operations/artifact_organization/artifact_organization_*.json`
- `tests/artifacts/archive/legacy/chaos/*` (legacy chaos run archive)

Privacy verification patterns:

- email addresses
- bearer tokens
- local user path segments (`/Users/<name>`, `/home/<name>`, `C:\Users\<name>`)
- secret-like JSON fields (`access_token`, `refresh_token`, `authorization`, `api_key`, `password`, `secret*`, `private_key`)

## 8) `make` Wrapper Map

`Makefile` provides compatibility targets that map to canonical commands.

| Make Target | Canonical Equivalent |
|---|---|
| `make up` | `./run demo` |
| `make down` | `./run stop` |
| `make stop` | `./run stop` |
| `make logs` | `./run logs` |
| `make clean` | `./run clean --wipe-data` |
| `make gate` | `./run gate` |
| `make dev` | `./run dev` |
| `make test` | `./run test` |
| `make test-seq` | `./run test --no-parallel` |
| `make test-no-open` | `./run test --no-open` |
| `make test-report` | `./run test --report` |
| `make test-clean` | `./run test --clean` |
| `make lint` | `./run lint` |
| `make docs-check` | `./run docs-check` |

Note: `make` also includes advanced targets (migrations, production scripts) that may call tooling directly.

## 9) Data Persistence and Safety Rules

- Default stop path: `./run stop` preserves database and state volumes.
- Default cleanup path: `./run clean` preserves volumes.
- Full reset path: `./run clean --wipe-data` deletes persisted volumes and user data.
- One-command reset + launch path: `./run demo --fresh`.

`./run verify formal scrub` and `./run verify mcp scrub` are privacy gates for report artifacts.
They do not reset databases or container volumes.

Never run destructive reset commands during normal restart workflows.

## 10) AI Operator Runbook (Chronological)

Use this sequence for deterministic automation and review:

1. `./run gate infra`
2. `./run gate lint`
3. `./run gate test`
4. `./run demo` (if service-level verification is required)
5. `./run status`
6. `./run stop` (end session without data loss)

If and only if a full re-initialization is explicitly required:

1. `./run demo --fresh`
2. Re-run setup/onboarding

## 11) Troubleshooting Escalation

Use low-level commands only after canonical commands fail:

- `docker compose ps`
- `docker compose logs -f <service>`
- `pytest ...` for targeted debugging
- `ea-agentgate ...` for direct CLI debugging

Always record the canonical command attempted first when filing an issue.
