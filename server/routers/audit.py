"""Audit log API routes."""

import csv
import io
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy import String, cast, func, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import col, select

from ..models import AuditEntry, AuditEntryRead, Permission, User, get_session
from ..utils.db import execute as db_execute
from .access_mode import route_access_mode
from .auth import require_permission

router = APIRouter(prefix="/audit", tags=["audit"])
limiter = Limiter(key_func=get_remote_address)


@dataclass(slots=True)
class AuditEntryFilters:
    """Query parameters used to filter audit log listings."""

    event_type: str | None = None
    actor: str | None = None
    tool: str | None = None
    search: str | None = None
    since: datetime | None = None
    until: datetime | None = None
    limit: int = Query(default=100, le=1000)
    offset: int = 0


def _sanitize_csv_cell(value: str | None) -> str:
    """Neutralize spreadsheet formula injection in CSV exports."""
    if value is None:
        return ""

    if value.startswith(("=", "+", "-", "@")):
        return f"'{value}"
    return value


@router.get("", response_model=list[AuditEntryRead])
@route_access_mode("read_only")
async def list_audit_entries(
    *,
    current_user: Annotated[User, Depends(require_permission(Permission.AUDIT_READ))],
    session: Annotated[AsyncSession, Depends(get_session)],
    filters: Annotated[AuditEntryFilters, Depends()],
):
    """List audit log entries with filters. Requires AUDIT_READ permission."""
    _ = current_user  # Used for permission check
    query = select(AuditEntry).order_by(col(AuditEntry.timestamp).desc())

    # Auditor scope is limited to entries where they are the actor.
    if current_user.role == "auditor":
        query = query.where(AuditEntry.actor == current_user.email)

    if filters.event_type:
        query = query.where(AuditEntry.event_type == filters.event_type)
    if filters.actor:
        query = query.where(AuditEntry.actor == filters.actor)
    if filters.tool:
        query = query.where(AuditEntry.tool == filters.tool)
    if filters.search:
        pattern = f"%{filters.search.lower()}%"
        query = query.where(
            or_(
                func.lower(cast(AuditEntry.actor, String)).like(pattern),
                func.lower(cast(AuditEntry.tool, String)).like(pattern),
                func.lower(cast(AuditEntry.event_type, String)).like(pattern),
                func.lower(cast(AuditEntry.details, String)).like(pattern),
            )
        )
    if filters.since:
        query = query.where(AuditEntry.timestamp >= filters.since)
    if filters.until:
        query = query.where(AuditEntry.timestamp <= filters.until)

    query = query.offset(filters.offset).limit(filters.limit)
    result = await db_execute(session, query)
    return result.scalars().all()


@router.get("/event-types")
@route_access_mode("read_only")
async def list_event_types(
    current_user: Annotated[User, Depends(require_permission(Permission.AUDIT_READ))],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Get list of distinct event types."""
    _ = current_user
    result = await db_execute(session, select(AuditEntry.event_type).distinct())
    results = result.scalars().all()
    return {"event_types": results}


@router.get("/actors")
@route_access_mode("read_only")
async def list_actors(
    current_user: Annotated[User, Depends(require_permission(Permission.AUDIT_READ))],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Get list of distinct actors."""
    _ = current_user
    result = await db_execute(
        session,
        select(AuditEntry.actor).distinct().where(col(AuditEntry.actor).is_not(None)),
    )
    results = result.scalars().all()
    return {"actors": results}


@router.get("/export")
@limiter.limit("10/minute")
@route_access_mode("read_only")
async def export_audit_log(
    request: Request,
    current_user: User = Depends(require_permission(Permission.AUDIT_EXPORT)),
    session: AsyncSession = Depends(get_session),
    export_format: str = Query(default="csv", pattern="^(csv|json)$", alias="format"),
    hours: int = Query(default=24, le=720),
):
    """Export audit log as CSV or JSON. Requires AUDIT_EXPORT permission.

    Rate limit: 10 requests per minute to prevent excessive bandwidth usage.
    """
    _ = request, current_user  # Used for rate limiting and permission check
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    result = await db_execute(
        session,
        select(AuditEntry).where(AuditEntry.timestamp >= since).order_by(col(AuditEntry.timestamp)),
    )
    entries = result.scalars().all()

    if export_format == "json":
        content = json.dumps(
            [
                {
                    "id": e.id,
                    "timestamp": e.timestamp.isoformat(),
                    "event_type": e.event_type,
                    "actor": e.actor,
                    "tool": e.tool,
                    "result": e.result,
                    "details": e.details,
                }
                for e in entries
            ],
            indent=2,
        )
        return StreamingResponse(
            io.StringIO(content),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=audit_log_{since.date()}.json"},
        )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp", "event_type", "actor", "tool", "result", "details"])

    for entry in entries:
        writer.writerow(
            [
                entry.timestamp.isoformat(),
                _sanitize_csv_cell(entry.event_type),
                _sanitize_csv_cell(entry.actor),
                _sanitize_csv_cell(entry.tool),
                _sanitize_csv_cell(entry.result),
                _sanitize_csv_cell(str(entry.details)),
            ]
        )

    output.seek(0)
    return StreamingResponse(
        output,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=audit_log_{since.date()}.csv"},
    )


@router.get("/stats")
@route_access_mode("read_only")
async def get_audit_stats(
    current_user: Annotated[User, Depends(require_permission(Permission.AUDIT_READ))],
    session: Annotated[AsyncSession, Depends(get_session)],
    hours: int = Query(default=24, le=720),
):
    """Get audit log statistics."""
    _ = current_user
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    result = await db_execute(session, select(AuditEntry).where(AuditEntry.timestamp >= since))
    entries = result.scalars().all()

    # Count by event type
    by_type: dict[str, int] = {}
    by_result: dict[str, int] = {}

    for e in entries:
        by_type[e.event_type] = by_type.get(e.event_type, 0) + 1
        if e.result:
            by_result[e.result] = by_result.get(e.result, 0) + 1

    return {
        "total_entries": len(entries),
        "by_event_type": by_type,
        "by_result": by_result,
        "period_hours": hours,
    }
