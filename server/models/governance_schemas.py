"""AI write-governance and validation-failure schemas."""

from datetime import datetime, timezone
from typing import Any, ClassVar

from sqlalchemy import Column, JSON
from sqlmodel import Field, SQLModel


def utc_now() -> datetime:
    """Get current UTC time as timezone-naive timestamp."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class AIChangeProposal(SQLModel, table=True):
    """Persisted AI write proposal requiring validation and optional review."""

    __tablename__: ClassVar[str] = "ai_change_proposals"

    id: int | None = Field(default=None, primary_key=True)
    proposal_id: str = Field(index=True, unique=True, max_length=64)
    owner_user_id: int | None = Field(default=None, foreign_key="users.id", index=True)
    owner_user_email: str | None = Field(default=None, index=True, max_length=255)
    governance_mode: str = Field(default="human_gated", index=True, max_length=32)
    status: str = Field(default="proposed", index=True, max_length=32)
    risk_class: str = Field(default="unknown", index=True, max_length=32)
    target_resource: str = Field(max_length=512)
    field_class: str = Field(default="unspecified", index=True, max_length=64)
    reason: str = Field(max_length=4096)
    proposal_payload: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    validator_output: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    validation_passed: bool | None = None
    requires_human_review: bool = Field(default=True)
    applied: bool = Field(default=False, index=True)
    reviewer_id: int | None = Field(default=None, foreign_key="users.id", index=True)
    reviewer_email: str | None = Field(default=None, index=True, max_length=255)
    reviewed_at: datetime | None = None
    applied_at: datetime | None = None
    created_at: datetime = Field(default_factory=utc_now, index=True)
    first_seen_at: datetime = Field(default_factory=utc_now, index=True)
    last_seen_at: datetime = Field(default_factory=utc_now, index=True)
    retry_count: int = Field(default=0)
    metadata_json: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))


class AIValidationFailure(SQLModel, table=True):
    """Error bucket for failed AI proposals and token integrity failures."""

    __tablename__: ClassVar[str] = "ai_validation_failures"

    id: int | None = Field(default=None, primary_key=True)
    failure_id: str = Field(index=True, unique=True, max_length=64)
    proposal_id: str | None = Field(default=None, index=True, max_length=64)
    related_session_id: str | None = Field(default=None, index=True, max_length=255)
    owner_user_id: int | None = Field(default=None, foreign_key="users.id", index=True)
    owner_user_email: str | None = Field(default=None, index=True, max_length=255)
    failure_type: str = Field(index=True, max_length=64)
    reason: str = Field(max_length=4096)
    status: str = Field(default="open", index=True, max_length=32)
    validator_output: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    payload: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    first_seen_at: datetime = Field(default_factory=utc_now, index=True)
    last_seen_at: datetime = Field(default_factory=utc_now, index=True)
    retry_count: int = Field(default=0)
    reviewer_id: int | None = Field(default=None, foreign_key="users.id", index=True)
    reviewer_email: str | None = Field(default=None, index=True, max_length=255)
    reviewed_at: datetime | None = None
    created_at: datetime = Field(default_factory=utc_now, index=True)
