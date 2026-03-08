# AgentGate Test Report (Archived Snapshot)

## Status

This file is retained as historical context for a one-time test remediation pass
completed on **2025-01-29**.

It is **not** the live source of truth for current test health.

## Current Source of Truth

Use the repository test runners directly:

```bash
./run gate test
./run test --no-open
./run test tests/security -q
```

Current test suites and structure are under `tests/`.

## Current Evidence Locations

- `allure-results/` and `allure-report/` for test run output
- `tests/artifacts/` for generated verification artifacts
- CI workflows under `.github/workflows/` for release gates

## Why This Was Pruned

The previous contents listed test files and metrics that no longer match the
current repository layout. Keeping that stale inventory created false signals
for contributors and reviewers.
