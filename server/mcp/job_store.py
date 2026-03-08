"""Persistent job store for async MCP operations."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, ClassVar
from uuid import uuid4

from sqlalchemy import Column, JSON, desc, inspect
from sqlmodel import Field, SQLModel, select

from server.models.database import engine, get_session_context
from server.utils.db import commit as db_commit, execute as db_execute, refresh as db_refresh
from server.metrics import record_mcp_async_job_failure

from .monitoring import emit_failure_alert
from .types_ground_truth import JobResponse, JobStatus


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class MCPAsyncJobRecord(SQLModel, table=True):
    """SQLModel table for MCP asynchronous job state persistence."""

    __tablename__: ClassVar[str] = "mcp_async_jobs"

    job_id: str = Field(primary_key=True, max_length=64)
    operation: str = Field(index=True, max_length=128)
    request_id: str = Field(index=True, max_length=64)
    status: str = Field(index=True, max_length=32)
    progress_pct: int = Field(default=0)
    message: str = Field(default="", max_length=2048)
    result_json: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    error_json: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    requires_input_payload_json: dict[str, Any] | None = Field(
        default=None,
        sa_column=Column(JSON),
    )
    started_at: datetime = Field(default_factory=_utc_now)
    updated_at: datetime = Field(default_factory=_utc_now)


_TABLE_INIT_LOCK = asyncio.Lock()


class _JobTableState:
    """Mutable state for one-time job-table initialization checks."""

    _initialized = False

    @classmethod
    def is_initialized(cls) -> bool:
        """Return True after table availability has been verified."""
        return cls._initialized

    @classmethod
    def mark_initialized(cls) -> None:
        """Mark table verification complete for this process lifetime."""
        cls._initialized = True


def _job_table_exists(sync_conn: Any) -> bool:
    """Return True when MCP async jobs table exists in the connected schema."""
    db_inspector = inspect(sync_conn)
    return bool(db_inspector.has_table(MCPAsyncJobRecord.__tablename__))


async def _ensure_table_initialized() -> None:
    if _JobTableState.is_initialized():
        return

    async with _TABLE_INIT_LOCK:
        if _JobTableState.is_initialized():
            return
        try:
            async with engine.begin() as conn:
                table_exists = await conn.run_sync(_job_table_exists)
        except Exception as exc:
            raise RuntimeError("Unable to verify MCP async job schema state.") from exc

        if not table_exists:
            raise RuntimeError(
                "MCP async job table 'mcp_async_jobs' is missing. "
                "Run migrations before serving async MCP operations."
            )

        _JobTableState.mark_initialized()


def _to_response(record: MCPAsyncJobRecord) -> JobResponse:
    return JobResponse(
        job_id=record.job_id,
        status=JobStatus(record.status),
        progress_pct=int(record.progress_pct),
        message=record.message,
        result=record.result_json,
        error=record.error_json,
        requires_input_payload=record.requires_input_payload_json,
        started_at=record.started_at,
        updated_at=record.updated_at,
        operation=record.operation,
        request_id=record.request_id,
    )


def new_request_id() -> str:
    """Create a deterministic-length request identifier."""
    return f"req_{uuid4().hex}"


def new_job_id() -> str:
    """Create a deterministic-length job identifier."""
    return f"job_{uuid4().hex}"


async def create_job(
    *,
    operation: str,
    request_id: str,
    status: JobStatus = JobStatus.QUEUED,
    progress_pct: int = 0,
    message: str = "",
    result: dict[str, Any] | None = None,
    error: dict[str, Any] | None = None,
    requires_input_payload: dict[str, Any] | None = None,
) -> JobResponse:
    """Persist a new MCP async job row and return its response model."""
    await _ensure_table_initialized()

    now = _utc_now()
    record = MCPAsyncJobRecord(
        job_id=new_job_id(),
        operation=operation,
        request_id=request_id,
        status=status.value,
        progress_pct=max(0, min(100, int(progress_pct))),
        message=message,
        result_json=result,
        error_json=error,
        requires_input_payload_json=requires_input_payload,
        started_at=now,
        updated_at=now,
    )

    async with get_session_context() as session:
        session.add(record)
        await db_commit(session)
        await db_refresh(session, record)

    return _to_response(record)


async def update_job(
    job_id: str,
    *,
    status: JobStatus | None = None,
    progress_pct: int | None = None,
    message: str | None = None,
    result: dict[str, Any] | None = None,
    error: dict[str, Any] | None = None,
    requires_input_payload: dict[str, Any] | None = None,
) -> JobResponse:
    """Update persisted job state and return the latest response payload."""
    await _ensure_table_initialized()

    async with get_session_context() as session:
        query = select(MCPAsyncJobRecord).where(MCPAsyncJobRecord.job_id == job_id)
        result_row = await db_execute(session, query)
        record = result_row.scalar_one_or_none()
        if record is None:
            raise KeyError(f"Unknown job_id: {job_id}")

        if status is not None:
            record.status = status.value
            if status is JobStatus.FAILED:
                record_mcp_async_job_failure(record.operation)
                await emit_failure_alert(
                    event_type="mcp_async_job_failure",
                    title="MCP asynchronous job failed",
                    description="An MCP async job entered failed state.",
                    severity="high",
                    correlation_id=record.request_id,
                    details={
                        "job_id": record.job_id,
                        "operation": record.operation,
                    },
                )
        if progress_pct is not None:
            record.progress_pct = max(0, min(100, int(progress_pct)))
        if message is not None:
            record.message = message
        if result is not None:
            record.result_json = result
        if error is not None:
            record.error_json = error
        if requires_input_payload is not None:
            record.requires_input_payload_json = requires_input_payload
        record.updated_at = _utc_now()

        session.add(record)
        await db_commit(session)
        await db_refresh(session, record)
        return _to_response(record)


async def get_job(job_id: str) -> JobResponse | None:
    """Fetch a single persisted job by id."""
    await _ensure_table_initialized()

    async with get_session_context() as session:
        query = select(MCPAsyncJobRecord).where(MCPAsyncJobRecord.job_id == job_id)
        result_row = await db_execute(session, query)
        record = result_row.scalar_one_or_none()
        if record is None:
            return None
        return _to_response(record)


async def list_jobs(
    *,
    status_filter: JobStatus | None = None,
    operation: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[JobResponse]:
    """List persisted jobs with optional status and operation filters."""
    await _ensure_table_initialized()

    bounded_limit = max(1, min(1000, int(limit)))
    bounded_offset = max(0, int(offset))

    async with get_session_context() as session:
        query = select(MCPAsyncJobRecord)
        if status_filter is not None:
            query = query.where(MCPAsyncJobRecord.status == status_filter.value)
        if operation:
            query = query.where(MCPAsyncJobRecord.operation == operation)
        query = query.order_by(desc(MCPAsyncJobRecord.updated_at))
        query = query.offset(bounded_offset).limit(bounded_limit)

        result_rows = await db_execute(session, query)
        records = result_rows.scalars().all()

    return [_to_response(record) for record in records]
