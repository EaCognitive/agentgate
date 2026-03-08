"""Trace execution-related schemas and models."""

from datetime import datetime, timezone
from typing import Any, ClassVar

from sqlmodel import SQLModel, Field
from sqlalchemy import Column, JSON

from .common_enums import TraceStatus


def utc_now() -> datetime:
    """Get current UTC time as timezone-naive (for TIMESTAMP WITHOUT TIME ZONE columns)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ============== Trace Models ==============
# (TraceStatus enum is imported from common_enums to maintain single source of truth)


# ============== Trace Models ==============


class Trace(SQLModel, table=True):
    """Database model for tool execution traces with inputs, outputs, and metadata."""

    __tablename__: ClassVar[str] = "traces"

    id: int | None = Field(default=None, primary_key=True)
    trace_id: str = Field(index=True)
    tool: str = Field(index=True)
    inputs: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    output: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    status: TraceStatus = Field(default=TraceStatus.PENDING, index=True)
    error: str | None = None
    blocked_by: str | None = None
    duration_ms: float | None = None
    cost: float = Field(default=0.0)
    agent_id: str | None = Field(default=None, index=True)
    session_id: str | None = Field(default=None, index=True)
    metadata_json: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    started_at: datetime = Field(default_factory=utc_now, index=True)
    ended_at: datetime | None = None
    created_by: int | None = Field(default=None, foreign_key="users.id", index=True)


class TraceCreate(SQLModel):
    """Schema for creating new trace records."""

    trace_id: str
    tool: str
    inputs: dict[str, Any] | None = None
    output: dict[str, Any] | None = None
    status: TraceStatus = TraceStatus.PENDING
    error: str | None = None
    blocked_by: str | None = None
    duration_ms: float | None = None
    cost: float = 0.0
    agent_id: str | None = None
    session_id: str | None = None


class TraceRead(SQLModel):
    """Schema for reading trace information from API endpoints."""

    id: int
    trace_id: str
    tool: str
    inputs: dict[str, Any] | None
    output: dict[str, Any] | None
    status: TraceStatus
    error: str | None
    blocked_by: str | None
    duration_ms: float | None
    cost: float
    agent_id: str | None
    session_id: str | None
    started_at: datetime
    ended_at: datetime | None
