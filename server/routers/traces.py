"""Trace routes.

Implements C-03 from the architectural audit: async database patterns
for scalable, non-blocking database operations.
"""

from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel
from sqlalchemy import desc, select as sqla_select
from sqlalchemy.sql.functions import count as sql_count, sum as sql_sum
from sqlalchemy.sql import func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select, col

from ..models import (
    Trace,
    TraceCreate,
    TraceRead,
    TraceStatus,
    get_session,
    User,
    UserRole,
)
from ..policy_governance.kernel.runtime_settings import get_scoped_reads_enabled
from ..utils.db import execute as db_execute, commit as db_commit, refresh as db_refresh
from .access_mode import route_access_mode
from .auth import get_current_user

router = APIRouter(prefix="/traces", tags=["traces"])


class TraceFilter(BaseModel):
    """Query filters for trace listing."""

    status: TraceStatus | None = None
    tool: str | None = None
    agent_id: str | None = None
    since: datetime | None = None
    limit: int = Query(default=100, le=1000)
    offset: int = 0


def _scoped_trace_query(
    query,
    *,
    current_user: User,
    scoped_reads_enabled: bool,
):
    if scoped_reads_enabled and current_user.role != "admin":
        return query.where(Trace.created_by == current_user.id)
    return query


@route_access_mode("read_only")
@router.get("", response_model=list[TraceRead])
async def list_traces(
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
    *,
    filters: TraceFilter = Depends(),
):
    """List traces with optional filters."""
    scoped_reads_enabled = await get_scoped_reads_enabled(session)
    query = _scoped_trace_query(
        select(Trace).order_by(desc(col(Trace.started_at))),
        current_user=current_user,
        scoped_reads_enabled=scoped_reads_enabled,
    )

    if filters.status:
        query = query.where(Trace.status == filters.status)
    if filters.tool:
        query = query.where(Trace.tool == filters.tool)
    if filters.agent_id:
        query = query.where(Trace.agent_id == filters.agent_id)
    if filters.since:
        query = query.where(Trace.started_at >= filters.since)

    query = query.offset(filters.offset).limit(filters.limit)
    result = await db_execute(session, query)
    return result.scalars().all()


@route_access_mode("read_only")
@router.get("/viewable", response_model=list[TraceRead])
async def list_viewable_traces(
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: int = Query(default=100, le=1000),
    offset: int = 0,
):
    """List traces visible to the caller under scoped read policy."""
    scoped_reads_enabled = await get_scoped_reads_enabled(session)
    query = _scoped_trace_query(
        select(Trace).order_by(desc(col(Trace.started_at))),
        current_user=current_user,
        scoped_reads_enabled=scoped_reads_enabled,
    )

    query = query.offset(offset).limit(limit)
    result = await db_execute(session, query)
    return result.scalars().all()


@route_access_mode("read_only")
@router.get("/stats")
async def get_trace_stats(
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
    hours: int = Query(default=24, le=168),
):
    """Get trace statistics for the last N hours."""
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=hours)
    scoped_reads_enabled = await get_scoped_reads_enabled(session)

    # Total counts by status
    query = _scoped_trace_query(
        select(Trace.status, sql_count(col(Trace.id)))
        .where(Trace.started_at >= since)
        .group_by(Trace.status),
        current_user=current_user,
        scoped_reads_enabled=scoped_reads_enabled,
    )
    result = await db_execute(
        session,
        query,
    )
    status_counts = result.all()

    counts = {s.value: 0 for s in TraceStatus}
    for status, count in status_counts:
        counts[status.value] = count

    total = sum(counts.values())

    return {
        "total": total,
        "success": counts["success"],
        "failed": counts["failed"],
        "blocked": counts["blocked"],
        "pending": counts["pending"],
        "success_rate": (counts["success"] / total * 100) if total > 0 else 0,
        "period_hours": hours,
    }


@route_access_mode("read_only")
@router.get("/timeline")
async def get_timeline(
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
    hours: int = Query(default=24, le=168),
    bucket_minutes: int = Query(default=60, ge=1, le=1440),
):
    """Get trace counts bucketed by time for charts."""
    if bucket_minutes < 1:
        raise HTTPException(
            status_code=422,
            detail="bucket_minutes must be >= 1",
        )
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=hours)
    scoped_reads_enabled = await get_scoped_reads_enabled(session)

    query = _scoped_trace_query(
        select(Trace.started_at, Trace.status)
        .where(Trace.started_at >= since)
        .order_by(col(Trace.started_at)),
        current_user=current_user,
        scoped_reads_enabled=scoped_reads_enabled,
    )
    result = await db_execute(
        session,
        query,
    )
    traces = result.all()

    # Bucket traces by time
    buckets: dict[str, dict[str, int]] = {}
    for started_at, status in traces:
        # Round to bucket
        bucket_time = started_at.replace(
            minute=(started_at.minute // bucket_minutes) * bucket_minutes,
            second=0,
            microsecond=0,
        )
        bucket_key = bucket_time.isoformat()

        if bucket_key not in buckets:
            buckets[bucket_key] = {"success": 0, "failed": 0, "blocked": 0}

        if status.value in buckets[bucket_key]:
            buckets[bucket_key][status.value] += 1

    return [{"time": k, **v} for k, v in sorted(buckets.items())]


@route_access_mode("read_only")
@router.get("/tools")
async def get_tool_stats(
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
    hours: int = Query(default=24, le=168),
):
    """Get per-tool statistics."""
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=hours)
    scoped_reads_enabled = await get_scoped_reads_enabled(session)
    tool_col = col(Trace.tool)
    status_col = col(Trace.status)
    started_at_col = col(Trace.started_at)

    query = _scoped_trace_query(
        sqla_select(
            tool_col,
            status_col,
            sql_count(col(Trace.id)),
            func.avg(col(Trace.duration_ms)),
            sql_sum(col(Trace.cost)),
        )
        .where(started_at_col >= since)
        .group_by(tool_col, status_col),
        current_user=current_user,
        scoped_reads_enabled=scoped_reads_enabled,
    )
    result = await db_execute(
        session,
        query,
    )
    results = result.all()

    # Aggregate by tool
    tools: dict[str, dict] = {}
    for tool, status, count, avg_duration, total_cost in results:
        if tool not in tools:
            tools[tool] = {
                "tool": tool,
                "total": 0,
                "success": 0,
                "blocked": 0,
                "failed": 0,
                "avg_duration_ms": 0,
                "total_cost": 0,
            }
        tools[tool]["total"] += count
        tools[tool][status.value] = count
        tools[tool]["avg_duration_ms"] = avg_duration or 0
        tools[tool]["total_cost"] += total_cost or 0

    return list(tools.values())


@route_access_mode("read_only")
@router.get("/{trace_id}", response_model=TraceRead)
async def get_trace(
    trace_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Get a single trace by ID."""
    result = await db_execute(session, select(Trace).where(Trace.trace_id == trace_id))
    trace = result.scalar_one_or_none()

    if not trace:
        raise HTTPException(status_code=404, detail="Trace not found")

    scoped_reads_enabled = await get_scoped_reads_enabled(session)
    if scoped_reads_enabled and current_user.role != "admin":
        if trace.created_by != current_user.id:
            raise HTTPException(status_code=404, detail="Trace not found")

    return trace


@route_access_mode("write_only")
@router.post("", response_model=TraceRead)
async def create_trace(
    trace_data: TraceCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Create a new trace (called by AgentGate library). Viewers cannot create traces."""
    # Viewers are read-only and cannot create traces
    if current_user.role in (UserRole.VIEWER, "viewer"):
        raise HTTPException(
            status_code=403,
            detail="Viewers cannot create traces",
        )
    trace = Trace.model_validate(trace_data)
    trace.created_by = current_user.id  # Set ownership
    session.add(trace)
    await db_commit(session)
    await db_refresh(session, trace)
    return trace
