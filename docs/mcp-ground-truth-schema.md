# MCP Policy-Governance Validation Schema

This document defines the MCP response contract used for long-running operations and validation artifacts.

## Scope

The schema is implemented in:

- `server/mcp/types_ground_truth.py`
- `server/mcp/tools_async.py`
- `server/mcp/job_store.py`

The goal is deterministic tool responses for both synchronous and asynchronous execution.

## Job Status Enum

`JobStatus` values:

- `queued`
- `running`
- `completed`
- `failed`
- `requires_input`

## JobResponse Contract

`JobResponse` fields:

- `job_id: str`
- `status: JobStatus`
- `progress_pct: int` (0-100)
- `message: str`
- `result: object | null`
- `error: object | null`
- `requires_input_payload: object | null`
- `started_at: datetime`
- `updated_at: datetime`
- `operation: str`
- `request_id: str`

## ToolEnvelope Contract

`ToolEnvelope` fields:

- `success: bool`
- `operation: str`
- `mode: "sync" | "async"`
- `request_id: str`
- `job: JobResponse | null`
- `result: object | null`
- `error: object | null`

## API Semantics

### Synchronous tool response

```json
{
  "success": true,
  "operation": "mcp_list_jobs",
  "mode": "sync",
  "request_id": "req_...",
  "result": {
    "jobs": [],
    "count": 0
  }
}
```

### Asynchronous tool response

```json
{
  "success": true,
  "operation": "mcp_synthesis_run",
  "mode": "async",
  "request_id": "req_...",
  "job": {
    "job_id": "job_...",
    "status": "queued",
    "progress_pct": 0,
    "message": "Synthesis run queued",
    "operation": "mcp_synthesis_run",
    "request_id": "req_...",
    "started_at": "2026-02-12T00:00:00Z",
    "updated_at": "2026-02-12T00:00:00Z"
  }
}
```

## Polling Contract

- Poll `mcp_check_job_status(job_id)` until status is terminal:
  - `completed`
  - `failed`
  - `requires_input`
- `mcp_list_jobs(...)` supports pagination and status filter.

## Validation

Policy-governance validation is executed with:

```bash
./run verify mcp policy-validation --profile dev --count 10000
```

Artifacts are written to:

- `tests/artifacts/algorithm/policy_governance_validation/`
