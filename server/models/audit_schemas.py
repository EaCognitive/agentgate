"""Audit log and cost tracking schemas and models."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, ClassVar

from sqlmodel import SQLModel, Field
from sqlalchemy import Column, JSON


def utc_now() -> datetime:
    """Get current UTC time as timezone-naive (for TIMESTAMP WITHOUT TIME ZONE columns)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ============== Security Threats ==============


class ThreatStatus(str, Enum):
    """Enum for security threat event lifecycle states."""

    PENDING = "pending"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class SecurityThreat(SQLModel, table=True):
    """Database model for persisted security threat events and their metadata."""

    __tablename__: ClassVar[str] = "security_threats"

    id: int | None = Field(default=None, primary_key=True)
    event_id: str = Field(index=True, unique=True, max_length=64)
    event_type: str = Field(index=True, max_length=64)
    severity: str = Field(index=True, max_length=16)
    status: ThreatStatus = Field(default=ThreatStatus.PENDING, index=True)
    source_ip: str | None = Field(default=None, max_length=64)
    target: str | None = Field(default=None, max_length=255)
    description: str | None = Field(default=None, max_length=512)
    detected_at: datetime = Field(default_factory=utc_now, index=True)
    acknowledged_at: datetime | None = None
    resolved_at: datetime | None = None
    dismissed_at: datetime | None = None
    user_id: int | None = Field(default=None, index=True)
    user_email: str | None = Field(default=None, max_length=255)
    metadata_json: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))


class SecurityThreatRead(SQLModel):
    """Schema for reading security threat information from API endpoints."""

    id: int
    event_id: str
    event_type: str
    severity: str
    status: ThreatStatus
    source_ip: str | None
    target: str | None
    description: str | None
    detected_at: datetime
    acknowledged_at: datetime | None
    resolved_at: datetime | None
    dismissed_at: datetime | None
    metadata_json: dict[str, Any] | None


# ============== System Settings ==============


class SystemSetting(SQLModel, table=True):
    """Database model for persistent system configuration settings."""

    __tablename__: ClassVar[str] = "system_settings"

    id: int | None = Field(default=None, primary_key=True)
    key: str = Field(index=True, unique=True, max_length=128)
    value: Any | None = Field(default=None, sa_column=Column(JSON))
    updated_at: datetime = Field(default_factory=utc_now)


class SystemSettingRead(SQLModel):
    """Schema for reading system settings from API endpoints."""

    key: str
    value: Any | None
    updated_at: datetime


# ============== Audit Log ==============


class AuditEntry(SQLModel, table=True):
    """Database model for compliance audit logs of system events and actions."""

    __tablename__: ClassVar[str] = "audit_log"

    id: int | None = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=utc_now, index=True)
    event_type: str = Field(index=True)
    actor: str | None = None
    tool: str | None = None
    inputs: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    result: str | None = None
    details: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    ip_address: str | None = None


class AuditEntryCreate(SQLModel):
    """Schema for creating audit log entries."""

    event_type: str
    actor: str | None = None
    tool: str | None = None
    inputs: dict[str, Any] | None = None
    result: str | None = None
    details: dict[str, Any] | None = None
    ip_address: str | None = None


class AuditEntryRead(SQLModel):
    """Schema for reading audit log entries from API endpoints."""

    id: int
    timestamp: datetime
    event_type: str
    actor: str | None
    tool: str | None
    result: str | None
    details: dict[str, Any] | None


# ============== Cost Tracking ==============


class CostRecord(SQLModel, table=True):
    """Database model for tracking tool execution costs and cost analytics."""

    __tablename__: ClassVar[str] = "cost_records"

    id: int | None = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=utc_now, index=True)
    tool: str = Field(index=True)
    cost: float
    trace_id: str | None = None
    agent_id: str | None = None


# ============== Dashboard Stats ==============


class OverviewStats(SQLModel):
    """Schema for dashboard overview statistics and metrics."""

    total_calls: int
    success_count: int
    blocked_count: int
    failed_count: int
    success_rate: float
    total_cost: float
    budget_limit: float | None
    pending_approvals: int


class CostBreakdown(SQLModel):
    """Schema for cost breakdown by tool in analytics."""

    tool: str
    total_cost: float
    call_count: int


class BlockBreakdown(SQLModel):
    """Schema for breakdown of blocked requests by middleware type."""

    middleware: str
    count: int
