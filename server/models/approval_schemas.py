"""Approval request-related schemas and models."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, ClassVar

from sqlmodel import SQLModel, Field
from sqlalchemy import Column, JSON


def utc_now() -> datetime:
    """Get current UTC time as timezone-naive (for TIMESTAMP WITHOUT TIME ZONE columns)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ============== Approval Enums ==============


class ApprovalStatus(str, Enum):
    """Enum for tool execution approval request lifecycle states."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


# ============== Approval Models ==============


class Approval(SQLModel, table=True):
    """Database model for tool execution approval requests pending human decision."""

    __tablename__: ClassVar[str] = "approvals"

    id: int | None = Field(default=None, primary_key=True)
    approval_id: str = Field(unique=True, index=True)
    tool: str
    inputs: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    trace_id: str | None = None
    agent_id: str | None = None
    session_id: str | None = None
    created_by_user_id: int | None = Field(default=None, foreign_key="users.id", index=True)
    created_by_email: str | None = Field(default=None, index=True)
    context: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    status: ApprovalStatus = Field(default=ApprovalStatus.PENDING, index=True)
    decided_by: str | None = None
    decision_reason: str | None = None
    created_at: datetime = Field(default_factory=utc_now, index=True)
    decided_at: datetime | None = None
    expires_at: datetime | None = None


class ApprovalCreate(SQLModel):
    """Schema for creating approval request records."""

    approval_id: str
    tool: str
    inputs: dict[str, Any] | None = None
    trace_id: str | None = None
    agent_id: str | None = None
    context: dict[str, Any] | None = None


class ApprovalRead(SQLModel):
    """Schema for reading approval request information from API endpoints."""

    id: int
    approval_id: str
    tool: str
    inputs: dict[str, Any] | None
    status: ApprovalStatus
    created_by_user_id: int | None
    created_by_email: str | None
    decided_by: str | None
    decision_reason: str | None
    created_at: datetime
    decided_at: datetime | None


class ApprovalDecision(SQLModel):
    """Schema for submitting approval or denial decisions on pending requests."""

    approved: bool
    reason: str | None = None
