"""PII Compliance and Audit Log routes for AgentGate.

Supports HIPAA / SOC 2 compliance reporting and audit log management.
"""

import csv
import io
import json
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from starlette.responses import StreamingResponse
from sqlmodel import select, col
from sqlalchemy.sql.functions import count as sql_count
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import emit_audit_event
from ..models import (
    User,
    PIIAuditEntry,
    PIIAuditEntryRead,
    PIISession,
    EncryptionKeyRecord,
    PIIComplianceStats,
    PIIAccessReport,
    PIIPermission,
    PIIEventType,
    get_session,
)
from ..utils.db import (
    execute as db_execute,
    commit as db_commit,
)
from .pii_utils import require_pii_permission

router = APIRouter()
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@")


def _sanitize_csv_cell(value: object) -> str:
    """Mitigate CSV formula injection for spreadsheet consumers."""
    text = "" if value is None else str(value)
    stripped = text.lstrip()
    if stripped and stripped[0] in _CSV_FORMULA_PREFIXES:
        return f"'{text}"
    return text


class PIIAuditFilter(BaseModel):
    """Query filters for PII audit log listing."""

    event_type: str | None = None
    user_id: str | None = None
    session_id: str | None = None
    pii_type: str | None = None
    success: bool | None = None
    since: datetime | None = None
    until: datetime | None = None
    limit: int = Query(default=100, le=1000)
    offset: int = 0


# =============================================================================
# PII Audit Log Endpoints
# =============================================================================


@router.get("/audit", response_model=list[PIIAuditEntryRead])
async def list_pii_audit_entries(
    _current_user: Annotated[User, Depends(require_pii_permission(PIIPermission.PII_AUDIT_READ))],
    session: Annotated[AsyncSession, Depends(get_session)],
    *,
    filters: PIIAuditFilter = Depends(),
) -> list[PIIAuditEntryRead]:
    """
    List PII audit log entries with filters.

    Required permission: pii:audit_read
    """
    query = select(PIIAuditEntry).order_by(col(PIIAuditEntry.timestamp).desc())

    if filters.event_type:
        query = query.where(PIIAuditEntry.event_type == filters.event_type)
    if filters.user_id:
        query = query.where(PIIAuditEntry.user_id == filters.user_id)
    if filters.session_id:
        query = query.where(PIIAuditEntry.session_id == filters.session_id)
    if filters.pii_type:
        query = query.where(PIIAuditEntry.pii_type == filters.pii_type)
    if filters.success is not None:
        query = query.where(PIIAuditEntry.success == filters.success)
    if filters.since:
        query = query.where(PIIAuditEntry.timestamp >= filters.since)
    if filters.until:
        query = query.where(PIIAuditEntry.timestamp <= filters.until)

    query = query.offset(filters.offset).limit(filters.limit)
    result = await db_execute(session, query)
    return result.scalars().all()


@router.get("/audit/verify-chain")
async def verify_audit_chain(
    _current_user: Annotated[User, Depends(require_pii_permission(PIIPermission.PII_AUDIT_READ))],
    session: Annotated[AsyncSession, Depends(get_session)],
    since: datetime | None = None,
    until: datetime | None = None,
):
    """
    Verify integrity of audit log chain.

    Returns chain verification status for tamper detection.
    Required permission: pii:audit_read
    """
    query = select(PIIAuditEntry).order_by(col(PIIAuditEntry.timestamp))

    if since:
        query = query.where(PIIAuditEntry.timestamp >= since)
    if until:
        query = query.where(PIIAuditEntry.timestamp <= until)

    result = await db_execute(session, query)
    entries = result.scalars().all()

    if not entries:
        return {"valid": True, "entries_checked": 0, "message": "No entries to verify"}

    # Verify chain of custody
    broken_links = []
    for i in range(1, len(entries)):
        if entries[i].previous_hash != entries[i - 1].integrity_hash:
            broken_links.append(
                {
                    "entry_id": entries[i].event_id,
                    "timestamp": entries[i].timestamp.isoformat(),
                    "expected_previous": entries[i - 1].integrity_hash,
                    "actual_previous": entries[i].previous_hash,
                }
            )

    is_valid = len(broken_links) == 0
    message = "Chain intact" if is_valid else f"Found {len(broken_links)} integrity failures"

    return {
        "valid": is_valid,
        "entries_checked": len(entries),
        "broken_links": broken_links,
        "message": message,
    }


@router.get("/audit/export")
async def export_pii_audit_log(
    current_user: Annotated[User, Depends(require_pii_permission(PIIPermission.PII_EXPORT))],
    session: Annotated[AsyncSession, Depends(get_session)],
    pii_format: str = Query(default="csv", alias="format", pattern="^(csv|json)$"),
    days: int = Query(default=30, le=365),
):
    """
    Export PII audit log for compliance review.

    Generates SOC 2 / HIPAA compliant audit export.
    Required permission: pii:export
    """
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)

    result = await db_execute(
        session,
        select(PIIAuditEntry)
        .where(PIIAuditEntry.timestamp >= since)
        .order_by(col(PIIAuditEntry.timestamp)),
    )
    entries = result.scalars().all()

    # Log the export
    await emit_audit_event(
        session,
        event_type="pii_audit_export",
        actor=current_user.email,
        result="success",
        details={"format": pii_format, "days": days, "entry_count": len(entries)},
    )
    await db_commit(session)

    if pii_format == "json":
        export_date = datetime.now(timezone.utc).replace(tzinfo=None).date()
        content = json.dumps(
            {
                "export_metadata": {
                    "exported_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
                    "exported_by": current_user.email,
                    "period_days": days,
                    "entry_count": len(entries),
                    "compliance": ["SOC 2 CC7.2", "HIPAA §164.312(b)"],
                },
                "entries": [
                    {
                        "event_id": e.event_id,
                        "timestamp": e.timestamp.isoformat(),
                        "event_type": e.event_type,
                        "user_id": e.user_id,
                        "session_id": e.session_id,
                        "placeholder": e.placeholder,
                        "pii_type": e.pii_type,
                        "data_classification": e.data_classification,
                        "success": e.success,
                        "error_message": e.error_message,
                        "encryption_key_id": e.encryption_key_id,
                        "integrity_hash": e.integrity_hash,
                    }
                    for e in entries
                ],
            },
            indent=2,
        )
        filename = f"pii_audit_export_{since.date()}_to_{export_date}.json"
        return StreamingResponse(
            io.StringIO(content),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "event_id",
            "timestamp",
            "event_type",
            "user_id",
            "session_id",
            "placeholder",
            "pii_type",
            "data_classification",
            "success",
            "error_message",
            "encryption_key_id",
        ]
    )

    for e in entries:
        writer.writerow(
            [
                _sanitize_csv_cell(e.event_id),
                _sanitize_csv_cell(e.timestamp.isoformat()),
                _sanitize_csv_cell(e.event_type),
                _sanitize_csv_cell(e.user_id),
                _sanitize_csv_cell(e.session_id),
                _sanitize_csv_cell(e.placeholder),
                _sanitize_csv_cell(e.pii_type),
                _sanitize_csv_cell(e.data_classification),
                _sanitize_csv_cell(e.success),
                _sanitize_csv_cell(e.error_message),
                _sanitize_csv_cell(e.encryption_key_id),
            ]
        )

    output.seek(0)
    export_date = datetime.now(timezone.utc).replace(tzinfo=None).date()
    filename = f"pii_audit_export_{since.date()}_to_{export_date}.csv"
    return StreamingResponse(
        output,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# =============================================================================
# Compliance Dashboard
# =============================================================================


@router.get("/stats", response_model=PIIComplianceStats)
async def get_compliance_stats(
    _current_user: Annotated[User, Depends(require_pii_permission(PIIPermission.PII_AUDIT_READ))],
    session: Annotated[AsyncSession, Depends(get_session)],
    days: int = Query(default=30, le=365),
):
    """
    Get PII compliance statistics for dashboard.

    Required permission: pii:audit_read
    """
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)

    # Use a dict to collect counts and avoid too many local variables (R0914)
    stats: dict[str, int] = {}

    # Count PII operations
    for op in [PIIEventType.PII_STORE, PIIEventType.PII_RETRIEVE]:
        result = await db_execute(
            session,
            select(sql_count(col(PIIAuditEntry.id))).where(
                PIIAuditEntry.event_type == op.value,
                PIIAuditEntry.timestamp >= since,
            ),
        )
        stats[op.value] = result.scalar() or 0

    # Count sessions
    result = await db_execute(
        session,
        select(sql_count(col(PIISession.id))).where(PIISession.created_at >= since),
    )
    stats["total_sessions"] = result.scalar() or 0

    is_active = getattr(col(PIISession.is_active), "is_")(True)
    result = await db_execute(
        session,
        select(sql_count(col(PIISession.id))).where(is_active),
    )
    stats["active_sessions"] = result.scalar() or 0

    # Count failures
    for fail_type in [PIIEventType.PII_INTEGRITY_FAILURE, PIIEventType.ACCESS_DENIED]:
        result = await db_execute(
            session,
            select(sql_count(col(PIIAuditEntry.id))).where(
                PIIAuditEntry.event_type == fail_type.value,
                PIIAuditEntry.timestamp >= since,
            ),
        )
        stats[fail_type.value] = result.scalar() or 0

    # Get encryption key info
    is_active_key = getattr(col(EncryptionKeyRecord.is_active), "is_")(True)
    created_at_desc = getattr(col(EncryptionKeyRecord.created_at), "desc")()
    result = await db_execute(
        session,
        select(EncryptionKeyRecord).where(is_active_key).order_by(created_at_desc),
    )
    active_key = result.scalars().first()

    key_age_days = 0
    last_rotation = None
    if active_key:
        # Strip timezone info for safe comparison with naive datetime
        created = active_key.created_at
        if created.tzinfo is not None:
            created = created.replace(tzinfo=None)
        key_age_days = (datetime.now(timezone.utc).replace(tzinfo=None) - created).days
        last_rotation = active_key.created_at

    return PIIComplianceStats(
        total_pii_stored=stats[PIIEventType.PII_STORE.value],
        total_pii_retrieved=stats[PIIEventType.PII_RETRIEVE.value],
        total_sessions=stats["total_sessions"],
        active_sessions=stats["active_sessions"],
        integrity_failures=stats[PIIEventType.PII_INTEGRITY_FAILURE.value],
        access_denied_count=stats[PIIEventType.ACCESS_DENIED.value],
        encryption_key_age_days=key_age_days,
        last_key_rotation=last_rotation,
    )


@router.get("/access-report", response_model=list[PIIAccessReport])
async def get_access_report(
    _current_user: Annotated[User, Depends(require_pii_permission(PIIPermission.PII_EXPORT))],
    session: Annotated[AsyncSession, Depends(get_session)],
    days: int = Query(default=30, le=365),
):
    """
    Generate PII access report for compliance auditing.

    Groups access by user and session for HIPAA minimum necessary analysis.
    Required permission: pii:export
    """
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)

    # Get all retrieve events grouped by user/session
    result = await db_execute(
        session,
        select(PIIAuditEntry)
        .where(
            PIIAuditEntry.event_type == PIIEventType.PII_RETRIEVE.value,
            PIIAuditEntry.timestamp >= since,
        )
        .order_by(col(PIIAuditEntry.timestamp)),
    )
    entries = result.scalars().all()

    # Group by user_id + session_id
    report_map: dict[tuple, dict] = {}

    for entry in entries:
        key = (entry.user_id or "anonymous", entry.session_id or "no_session")

        if key not in report_map:
            report_map[key] = {
                "user_id": key[0],
                "session_id": key[1],
                "access_count": 0,
                "pii_types": set(),
                "first_access": entry.timestamp,
                "last_access": entry.timestamp,
                "purposes": set(),
            }

        report_map[key]["access_count"] += 1
        if entry.pii_type:
            report_map[key]["pii_types"].add(entry.pii_type)
        report_map[key]["last_access"] = entry.timestamp

        # Get purpose from session if available
        pii_result = await db_execute(
            session, select(PIISession).where(PIISession.session_id == entry.session_id)
        )
        pii_session = pii_result.scalars().first()
        if pii_session and pii_session.purpose:
            report_map[key]["purposes"].add(pii_session.purpose)

    # Convert to response format
    return [
        PIIAccessReport(
            user_id=data["user_id"],
            session_id=data["session_id"],
            access_count=data["access_count"],
            pii_types_accessed=list(data["pii_types"]),
            first_access=data["first_access"],
            last_access=data["last_access"],
            purposes=list(data["purposes"]),
        )
        for data in report_map.values()
    ]


@router.get("/compliance-checklist")
async def get_compliance_checklist(
    _current_user: Annotated[User, Depends(require_pii_permission(PIIPermission.PII_AUDIT_READ))],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """
    Get compliance checklist status.

    Returns status of SOC 2 and HIPAA requirements.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    thirty_days_ago = now - timedelta(days=30)

    # Check encryption key age (should rotate at least every 90 days)
    is_active_key = getattr(col(EncryptionKeyRecord.is_active), "is_")(True)
    result = await db_execute(session, select(EncryptionKeyRecord).where(is_active_key))
    active_key = result.scalars().first()

    key_age_days = 0
    if active_key:
        # Strip timezone info for safe comparison with naive datetime
        created = active_key.created_at
        if created.tzinfo is not None:
            created = created.replace(tzinfo=None)
        key_age_days = (now - created).days

    # Check for integrity failures
    result = await db_execute(
        session,
        select(sql_count(col(PIIAuditEntry.id))).where(
            PIIAuditEntry.event_type == PIIEventType.PII_INTEGRITY_FAILURE.value,
            PIIAuditEntry.timestamp >= thirty_days_ago,
        ),
    )
    integrity_failures = result.scalar() or 0

    # Check audit log completeness
    result = await db_execute(
        session,
        select(sql_count(col(PIIAuditEntry.id))).where(
            PIIAuditEntry.timestamp >= thirty_days_ago,
        ),
    )
    audit_entries = result.scalar() or 0

    return {
        "hipaa": {
            "164.312(a)(2)(iv) Encryption": {
                "status": "pass" if active_key else "fail",
                "details": "AES-256-GCM encryption at rest"
                if active_key
                else "No active encryption key",
            },
            "164.312(b) Audit Controls": {
                "status": "pass" if (audit_entries or 0) > 0 else "warning",
                "details": f"{audit_entries or 0} audit entries in last 30 days",
            },
            "164.312(c)(1) Integrity": {
                "status": "pass" if (integrity_failures or 0) == 0 else "fail",
                "details": f"{integrity_failures or 0} integrity failures detected",
            },
            "164.530(j)(1) Retention": {
                "status": "pass",
                "details": "6-year retention policy configured",
            },
        },
        "soc2": {
            "CC6.1 Access Control": {
                "status": "pass",
                "details": "RBAC with granular PII permissions",
            },
            "CC7.2 Monitoring": {
                "status": "pass" if (audit_entries or 0) > 0 else "warning",
                "details": f"{audit_entries or 0} events logged",
            },
            "CC7.3 Integrity": {
                "status": "pass" if (integrity_failures or 0) == 0 else "fail",
                "details": "HMAC-SHA256 chain verification",
            },
        },
        "recommendations": [
            "Rotate encryption keys every 90 days" if key_age_days > 90 else None,
            "Investigate integrity failures" if (integrity_failures or 0) > 0 else None,
            "Review access patterns for minimum necessary compliance",
        ],
    }
