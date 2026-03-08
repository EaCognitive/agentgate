"""Identity, risk, and policy decision schemas.

This module provides:
- Canonical principal and provider-link records
- Scoped role bindings for authorization decisions
- Baseline risk profile persistence
- Session assurance and policy decision audit records
- Verification grant records for sensitive security workflows
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, ClassVar

from sqlalchemy import Column, JSON, UniqueConstraint, Index
from sqlmodel import Field, SQLModel


def utc_now() -> datetime:
    """Return current UTC timestamp as timezone-naive database value."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class PrincipalType(str, Enum):
    """Supported principal categories for authorization contexts."""

    HUMAN_USER = "human_user"
    AGENT_SERVICE = "agent_service"
    MCP_CLIENT = "mcp_client"


class PrincipalRiskLevel(str, Enum):
    """Baseline and effective risk levels used by policy evaluation."""

    R0 = "R0"
    R1 = "R1"
    R2 = "R2"
    R3 = "R3"
    R4 = "R4"


class SessionAssuranceLevel(str, Enum):
    """Session assurance levels derived from authentication posture."""

    A1 = "A1"
    A2 = "A2"
    A3 = "A3"


class ChannelTrustLevel(str, Enum):
    """Channel trust levels used in risk model evaluation."""

    C0 = "C0"
    C1 = "C1"
    C2 = "C2"
    C3 = "C3"


class ActionSensitivityLevel(str, Enum):
    """Action sensitivity levels used in risk model evaluation."""

    S0 = "S0"
    S1 = "S1"
    S2 = "S2"
    S3 = "S3"
    S4 = "S4"


class RuntimeThreatLevel(str, Enum):
    """Dynamic runtime threat levels used in risk model evaluation."""

    T0 = "T0"
    T1 = "T1"
    T2 = "T2"
    T3 = "T3"
    T4 = "T4"


class PIIObligationProfile(str, Enum):
    """PII policy obligation profile for channel and viewer controls."""

    STRICT_TOKENIZED = "strict_tokenized"
    TRUSTED_RESTORE_RUNTIME_ONLY = "trusted_restore_runtime_only"
    FULL_RESTORE_FOR_AUTHORIZED_VIEWERS = "full_restore_for_authorized_viewers"


class IdentityPrincipal(SQLModel, table=True):
    """Canonical principal record for users, agents, and MCP clients."""

    __tablename__: ClassVar[str] = "identity_principals"
    __table_args__ = (Index("ix_identity_principal_subject_tenant", "subject_id", "tenant_id"),)

    id: int | None = Field(default=None, primary_key=True)
    principal_id: str = Field(index=True, unique=True, max_length=64)
    principal_type: str = Field(index=True, max_length=32)
    subject_id: str = Field(index=True, max_length=255)
    tenant_id: str = Field(default="default", index=True, max_length=128)
    provider: str = Field(default="local", index=True, max_length=64)
    provider_subject: str | None = Field(default=None, index=True, max_length=255)
    display_name: str | None = Field(default=None, max_length=255)
    metadata_json: dict[str, Any] = Field(
        default_factory=dict, sa_column=Column(JSON, nullable=False)
    )
    is_active: bool = Field(default=True, index=True)
    created_at: datetime = Field(default_factory=utc_now, index=True)
    updated_at: datetime = Field(default_factory=utc_now, index=True)


class IdentityLink(SQLModel, table=True):
    """Mapping between provider subject identifiers and internal principals."""

    __tablename__: ClassVar[str] = "identity_links"
    __table_args__ = (
        UniqueConstraint(
            "provider",
            "provider_subject",
            "tenant_id",
            name="uq_identity_links_provider_subject_tenant",
        ),
    )

    id: int | None = Field(default=None, primary_key=True)
    provider: str = Field(index=True, max_length=64)
    provider_subject: str = Field(index=True, max_length=255)
    principal_id: str = Field(index=True, max_length=64)
    tenant_id: str = Field(default="default", index=True, max_length=128)
    user_id: int | None = Field(default=None, foreign_key="users.id", index=True)
    created_at: datetime = Field(default_factory=utc_now, index=True)
    last_seen_at: datetime = Field(default_factory=utc_now, index=True)


class RoleBinding(SQLModel, table=True):
    """Scoped role assignment record with provenance and expiry metadata."""

    __tablename__: ClassVar[str] = "role_bindings"
    __table_args__ = (
        UniqueConstraint(
            "principal_id",
            "role",
            "scope_type",
            "scope_id",
            name="uq_role_bindings_principal_role_scope",
        ),
    )

    id: int | None = Field(default=None, primary_key=True)
    principal_id: str = Field(index=True, max_length=64)
    role: str = Field(index=True, max_length=64)
    scope_type: str = Field(default="tenant", index=True, max_length=32)
    scope_id: str = Field(default="default", index=True, max_length=255)
    source: str = Field(default="system", max_length=64)
    metadata_json: dict[str, Any] = Field(
        default_factory=dict, sa_column=Column(JSON, nullable=False)
    )
    created_at: datetime = Field(default_factory=utc_now, index=True)
    expires_at: datetime | None = Field(default=None, index=True)
    created_by_user_id: int | None = Field(default=None, foreign_key="users.id")


class RiskProfile(SQLModel, table=True):
    """Baseline risk profile assigned to a principal."""

    __tablename__: ClassVar[str] = "risk_profiles"

    id: int | None = Field(default=None, primary_key=True)
    principal_id: str = Field(index=True, unique=True, max_length=64)
    principal_type: str = Field(index=True, max_length=32)
    risk_level: str = Field(default=PrincipalRiskLevel.R1.value, index=True, max_length=4)
    reason: str | None = Field(default=None, max_length=1024)
    reviewed_by: str | None = Field(default=None, max_length=255)
    metadata_json: dict[str, Any] = Field(
        default_factory=dict, sa_column=Column(JSON, nullable=False)
    )
    created_at: datetime = Field(default_factory=utc_now, index=True)
    updated_at: datetime = Field(default_factory=utc_now, index=True)


class SessionAssuranceEvent(SQLModel, table=True):
    """Session assurance and step-up state transition log."""

    __tablename__: ClassVar[str] = "session_assurance_events"

    id: int | None = Field(default=None, primary_key=True)
    event_id: str = Field(index=True, unique=True, max_length=64)
    principal_id: str = Field(index=True, max_length=64)
    session_id: str | None = Field(default=None, index=True, max_length=255)
    assurance_level: str = Field(index=True, max_length=4)
    provider: str | None = Field(default=None, max_length=64)
    method: str | None = Field(default=None, max_length=64)
    event_type: str = Field(index=True, max_length=64)
    metadata_json: dict[str, Any] = Field(
        default_factory=dict, sa_column=Column(JSON, nullable=False)
    )
    created_at: datetime = Field(default_factory=utc_now, index=True)


class PolicyDecisionRecord(SQLModel, table=True):
    """Immutable policy decision log for sensitive authorization paths."""

    __tablename__: ClassVar[str] = "policy_decisions"
    __table_args__ = (Index("ix_policy_decision_principal_created", "principal_id", "created_at"),)

    id: int | None = Field(default=None, primary_key=True)
    decision_id: str = Field(index=True, unique=True, max_length=64)
    principal_id: str = Field(index=True, max_length=64)
    tenant_id: str = Field(default="default", index=True, max_length=128)
    action: str = Field(index=True, max_length=255)
    resource: str = Field(max_length=1024)
    allowed: bool = Field(index=True)
    reason: str | None = Field(default=None, max_length=1024)
    effective_risk: str = Field(index=True, max_length=4)
    required_assurance: str = Field(max_length=4)
    session_assurance: str = Field(max_length=4)
    required_step_up: bool = Field(default=False)
    required_approval: bool = Field(default=False)
    obligations_json: list[str] = Field(
        default_factory=list, sa_column=Column(JSON, nullable=False)
    )
    trace_id: str | None = Field(default=None, index=True, max_length=128)
    created_at: datetime = Field(default_factory=utc_now, index=True)


class VerificationGrant(SQLModel, table=True):
    """Short-lived grant token for verification and penetration workflows."""

    __tablename__: ClassVar[str] = "verification_grants"

    id: int | None = Field(default=None, primary_key=True)
    grant_token: str = Field(index=True, unique=True, max_length=256)
    principal_id: str = Field(index=True, max_length=64)
    user_id: int | None = Field(default=None, foreign_key="users.id", index=True)
    tenant_id: str = Field(default="default", index=True, max_length=128)
    purpose: str = Field(index=True, max_length=255)
    risk_level: str = Field(index=True, max_length=4)
    required_assurance: str = Field(max_length=4)
    issued_at: datetime = Field(default_factory=utc_now, index=True)
    expires_at: datetime = Field(index=True)
    used_at: datetime | None = Field(default=None, index=True)
    revoked: bool = Field(default=False, index=True)
    metadata_json: dict[str, Any] = Field(
        default_factory=dict, sa_column=Column(JSON, nullable=False)
    )


class AuthorizationContext(SQLModel):
    """Canonical authorization context resolved before policy decisions."""

    subject_id: str
    principal_type: str
    tenant_id: str
    roles: list[str] = Field(default_factory=list)
    scopes: list[str] = Field(default_factory=list)
    principal_risk: str = PrincipalRiskLevel.R1.value
    session_assurance: str = SessionAssuranceLevel.A1.value
    channel_id: str | None = None
    agent_id: str | None = None
    trace_id: str | None = None
    provider: str = "local"
    provider_subject: str | None = None


class PolicyDecision(SQLModel):
    """Policy decision response used by authorization and risk endpoints."""

    allowed: bool
    reason: str
    required_step_up: bool = False
    required_approval: bool = False
    obligations: list[str] = Field(default_factory=list)
    decision_id: str
    effective_risk: str
    required_assurance: str
    session_assurance: str
