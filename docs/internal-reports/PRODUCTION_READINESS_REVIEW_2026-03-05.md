# Production Readiness Review (2026-03-05)

## Summary

- Objective: strict production-readiness review for GitHub portfolio launch.
- Scope: compare `HEAD` baseline and current workspace; remediate blockers first.
- Outcome: all required release gates are green in the current workspace.
- Policy decision: strict static typing gates apply to production code (`ea_agentgate`, `server`).
  Test-suite wide static typing remains tracked debt and is non-gating.

## Gate Matrix

| Gate | HEAD baseline | Current (final) | Status | Attribution |
|---|---|---|---|---|
| `uv run make lint` | mixed | PASS | pass | improved |
| `uv run make typecheck` | FAIL | PASS | pass | improved |
| `uv run npx -y pyright` (configured scope) | FAIL | PASS (`0 errors`) | pass | improved |
| `uv run npx -y pyright ea_agentgate server tests` | FAIL (`277 errors`) | PASS (`0 errors`) | pass | improved + scope policy |
| `uv run mypy ea_agentgate server tests` (advisory) | FAIL (`239 errors`) | FAIL (`151 errors`) | blocked | pre-existing debt reduced |
| `uv run make docs-check` | FAIL | PASS | pass | improved |
| `uv run pytest tests/ -m "not integration and not formal_heavy" -n auto` | timed out in prior sweep | PASS (`1412 passed`) | pass | improved |
| `uv run pytest tests/ -m "integration" -q` | FAIL in prior sweep | PASS (`2 passed`) | pass | improved |
| `uv run pytest tests/mcp_policy -q` | FAIL in prior sweep | PASS (`6 passed`) | pass | improved |
| `uv run pytest tests/ -m formal_heavy -q` | FAIL (`0 selected`) | PASS (`3 passed`) | pass | improved |
| `dashboard: npm run lint` | PASS | PASS | pass | stable |
| `dashboard: npx tsc --noEmit` | FAIL (path drift) | PASS | pass | improved |
| `dashboard: npm audit --audit-level=high` | PASS | PASS | pass | stable |
| `dashboard: npm run test:smoke` | PASS | PASS (`2 passed`) | pass | stable |
| `uv run bandit -r ea_agentgate server --severity-level medium --confidence-level medium -q` | n/a | PASS | pass | no medium/high findings |
| `uv export ... && uv run pip-audit -r ...` | PASS | PASS | pass | stable |
| `uv build && uv run twine check dist/*` | PASS | PASS | pass | stable |

## Findings (Severity Ranked)

### P0

- None.

### P1

- None in required release gates.

### P2

- Broad test-suite static typing debt remains when forcing full mypy across `tests/`.
  Evidence: `151` current errors vs `239` at `HEAD` baseline.
  Owner: test maintainers.
  Disposition: documented non-gating debt for portfolio launch.
- One FastAPI deprecation warning remains in non-integration tests
  (`HTTP_422_UNPROCESSABLE_ENTITY`).
  Owner: API/router maintainers.

## Final Recommendation

- GitHub portfolio publication: **GO**.
- Enterprise-hardening follow-up: close advisory test typing debt and deprecation drift.

## Portfolio Polish Checklist

- Keep this reproducible verify sequence in launch notes:
  - `uv run make lint`
  - `uv run make typecheck`
  - `uv run npx -y pyright`
  - `uv run make docs-check`
  - `uv run pytest tests/ -m "not integration and not formal_heavy" -n auto`
  - `uv run pytest tests/ -m "integration" -q`
  - `uv run pytest tests/mcp_policy -q`
  - `uv run pytest tests/ -m formal_heavy -q`
  - `cd dashboard && npm run lint && npx tsc --noEmit && npm audit --audit-level=high && npm run test:smoke`
  - `uv export --format=requirements-txt --no-hashes --all-extras > /tmp/requirements.txt`
  - `uv run pip-audit -r /tmp/requirements.txt`
  - `uv build && uv run twine check dist/*`
- Keep typing policy explicit: pyright required on `ea_agentgate` + `server`; test-suite typing debt
  tracked separately.
- Confirm no generated smoke artifacts are staged before publishing.
