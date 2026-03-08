"""Approval workflow API routes."""

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select, col

from ..models import (
    Approval,
    ApprovalCreate,
    ApprovalRead,
    ApprovalStatus,
    ApprovalDecision,
    AuditEntry,
    get_session,
    Permission,
    User,
)
from ..utils.db import execute as db_execute, commit as db_commit, refresh as db_refresh
from .access_mode import route_access_mode
from .auth import get_current_user, require_permission

router = APIRouter(prefix="/approvals", tags=["approvals"])


@router.get("", response_model=list[ApprovalRead])
@route_access_mode("read_only")
async def list_approvals(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(require_permission(Permission.APPROVAL_READ))],
    status: ApprovalStatus | None = None,
    limit: int = Query(default=50, le=500),
    offset: int = 0,
):
    """List approval requests. Requires APPROVAL_READ permission."""
    _ = current_user  # Used for authentication only
    query = select(Approval).order_by(col(Approval.created_at).desc())

    if status:
        query = query.where(Approval.status == status)

    query = query.offset(offset).limit(limit)
    result = await db_execute(session, query)
    return result.scalars().all()


@router.get("/pending", response_model=list[ApprovalRead])
@route_access_mode("read_only")
async def list_pending(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(require_permission(Permission.APPROVAL_READ))],
):
    """List pending approval requests. Requires APPROVAL_READ permission."""
    _ = current_user  # Used for authentication only
    result = await db_execute(
        session,
        select(Approval)
        .where(Approval.status == ApprovalStatus.PENDING)
        .order_by(col(Approval.created_at)),
    )
    return result.scalars().all()


@router.get("/pending/count")
@route_access_mode("read_only")
async def count_pending(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(require_permission(Permission.APPROVAL_READ))],
):
    """Get count of pending approvals. Requires APPROVAL_READ permission."""
    _ = current_user  # Used for authentication only
    result = await db_execute(
        session, select(Approval).where(Approval.status == ApprovalStatus.PENDING)
    )
    approvals = result.scalars().all()
    return {"count": len(approvals)}


@router.get("/{approval_id}", response_model=ApprovalRead)
@route_access_mode("read_only")
async def get_approval(
    approval_id: str,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(require_permission(Permission.APPROVAL_READ))],
):
    """Get a single approval request. Requires APPROVAL_READ permission."""
    _ = current_user  # Used for authentication only
    result = await db_execute(session, select(Approval).where(Approval.approval_id == approval_id))
    approval = result.scalar_one_or_none()

    if not approval:
        raise HTTPException(status_code=404, detail="Approval not found")

    return approval


@router.post("/{approval_id}/decide", response_model=ApprovalRead)
@route_access_mode("write_only")
async def decide_approval(
    approval_id: str,
    decision: ApprovalDecision,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(require_permission(Permission.APPROVAL_DECIDE))],
):
    """Approve or deny a request. Requires APPROVAL_DECIDE permission.

    The authenticated user will be recorded as the decision maker.
    """
    result = await db_execute(session, select(Approval).where(Approval.approval_id == approval_id))
    approval = result.scalar_one_or_none()

    if not approval:
        raise HTTPException(status_code=404, detail="Approval not found")

    if approval.status != ApprovalStatus.PENDING:
        raise HTTPException(
            status_code=400,
            detail=f"Approval already {approval.status.value}",
        )

    # Update approval
    approval.status = ApprovalStatus.APPROVED if decision.approved else ApprovalStatus.DENIED
    approval.decided_by = current_user.email  # Use actual authenticated user
    approval.decided_at = datetime.now(timezone.utc)
    approval.decision_reason = decision.reason

    session.add(approval)

    # Audit log
    session.add(
        AuditEntry(
            event_type="approval_decision",
            actor=current_user.email,  # Use actual authenticated user
            tool=approval.tool,
            inputs=approval.inputs,
            result="approved" if decision.approved else "denied",
            details={
                "approval_id": approval_id,
                "reason": decision.reason,
            },
        )
    )

    await db_commit(session)
    await db_refresh(session, approval)

    return approval


@router.post("", response_model=ApprovalRead)
@route_access_mode("write_only")
async def create_approval(
    approval_data: ApprovalCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Create a new approval request (called by AgentGate library)."""
    _ = current_user
    approval = Approval.model_validate(approval_data)
    session.add(approval)
    await db_commit(session)
    await db_refresh(session, approval)
    return approval
