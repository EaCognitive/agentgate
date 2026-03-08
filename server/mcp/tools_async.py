"""MCP tools and helpers for asynchronous ground-truth job workflows."""

from __future__ import annotations

from typing import Any

from .api_client import MCPApiClientError
from .auth_session import auth_error_payload, enforce_mcp_policy, require_mcp_auth
from .execution_policy import ExecutionPolicyError, enforce_execution_policy
from .job_store import get_job, list_jobs, new_request_id
from .tools_api import MCPToolExecutionError
from .types_ground_truth import JobResponse, JobStatus, ToolEnvelope


def build_async_envelope(operation: str, request_id: str, job: JobResponse) -> str:
    """Build a standard asynchronous response envelope."""
    return ToolEnvelope(
        success=True,
        operation=operation,
        mode="async",
        request_id=request_id,
        job=job,
    ).model_dump_json(indent=2)


def build_sync_envelope(
    *,
    operation: str,
    request_id: str,
    result: dict[str, Any],
    success: bool = True,
) -> str:
    """Build a standard synchronous response envelope."""
    return ToolEnvelope(
        success=success,
        operation=operation,
        mode="sync",
        request_id=request_id,
        result=result,
    ).model_dump_json(indent=2)


def build_error_envelope(
    *,
    operation: str,
    request_id: str,
    status_code: int,
    message: str,
    details: dict[str, Any] | None = None,
) -> str:
    """Build a deterministic error envelope for MCP job operations."""
    return ToolEnvelope(
        success=False,
        operation=operation,
        mode="sync",
        request_id=request_id,
        error={
            "status_code": status_code,
            "message": message,
            "details": details or {},
        },
    ).model_dump_json(indent=2)


def _parse_job_status(value: str) -> JobStatus | None:
    if not value:
        return None
    normalized = value.strip().lower()
    for candidate in JobStatus:
        if candidate.value == normalized:
            return candidate
    raise MCPToolExecutionError(
        build_error_envelope(
            operation="mcp_list_jobs",
            request_id=new_request_id(),
            status_code=422,
            message=f"Invalid status_filter: {value}",
            details={"valid_statuses": [item.value for item in JobStatus]},
        )
    )


async def _require_auth(operation: str, context: dict[str, Any], *, method: str, path: str) -> None:
    payload = {"method": method, "path": path, **context}
    try:
        await require_mcp_auth()
        await enforce_mcp_policy(operation, payload)
        await enforce_execution_policy(operation, method=method, context=payload)
    except MCPApiClientError as exc:
        raise MCPToolExecutionError(
            ToolEnvelope(
                success=False,
                operation=operation,
                mode="sync",
                request_id=new_request_id(),
                error=auth_error_payload(exc, operation),
            ).model_dump_json(indent=2)
        ) from exc
    except ExecutionPolicyError as exc:
        raise MCPToolExecutionError(
            ToolEnvelope(
                success=False,
                operation=operation,
                mode="sync",
                request_id=new_request_id(),
                error=exc.payload,
            ).model_dump_json(indent=2)
        ) from exc


async def mcp_check_job_status(job_id: str) -> str:
    """Retrieve current status for an asynchronous MCP operation."""
    request_id = new_request_id()
    await _require_auth(
        "mcp_check_job_status",
        {"job_id": job_id},
        method="GET",
        path=f"/mcp/jobs/{job_id}",
    )

    job = await get_job(job_id)
    if job is None:
        return build_error_envelope(
            operation="mcp_check_job_status",
            request_id=request_id,
            status_code=404,
            message=f"Job not found: {job_id}",
            details={"job_id": job_id},
        )

    return build_async_envelope("mcp_check_job_status", request_id, job)


async def mcp_list_jobs(
    status_filter: str = "",
    operation: str = "",
    limit: int = 100,
    offset: int = 0,
) -> str:
    """List asynchronous MCP jobs with optional filtering and pagination."""
    request_id = new_request_id()
    await _require_auth(
        "mcp_list_jobs",
        {
            "status_filter": status_filter,
            "operation_filter": operation,
            "limit": limit,
            "offset": offset,
        },
        method="GET",
        path="/mcp/jobs",
    )

    parsed_status = _parse_job_status(status_filter)
    jobs = await list_jobs(
        status_filter=parsed_status,
        operation=operation or None,
        limit=limit,
        offset=offset,
    )

    return build_sync_envelope(
        operation="mcp_list_jobs",
        request_id=request_id,
        result={
            "jobs": [job.model_dump(mode="json") for job in jobs],
            "count": len(jobs),
            "filters": {
                "status_filter": parsed_status.value if parsed_status else "",
                "operation": operation,
                "limit": limit,
                "offset": offset,
            },
        },
    )
