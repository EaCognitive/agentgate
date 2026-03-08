"""PII vault compliance and encryption key management schemas and models."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, ClassVar

from sqlmodel import SQLModel, Field
from sqlalchemy import Column, JSON, UniqueConstraint

# PIIPermission is defined in common_enums for single source of truth
# and is re-exported from server.models.__init__


def utc_now() -> datetime:
    """Get current UTC time as timezone-naive (for TIMESTAMP WITHOUT TIME ZONE columns)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ============== PII Vault Compliance (SOC 2 / HIPAA) ==============


class PIIDataClassification(str, Enum):
    """Data classification levels for HIPAA compliance."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"  # PHI/ePHI falls here


class PIIEventType(str, Enum):
    """PII-specific audit event types."""

    PII_STORE = "pii_store"
    PII_RETRIEVE = "pii_retrieve"
    PII_DELETE = "pii_delete"
    PII_BULK_RETRIEVE = "pii_bulk_retrieve"
    PII_CLEAR_SESSION = "pii_clear_session"
    PII_INTEGRITY_FAILURE = "pii_integrity_failure"
    PII_DECRYPTION_FAILURE = "pii_decryption_failure"
    ACCESS_DENIED = "access_denied"
    KEY_ROTATION = "key_rotation"


class PIIAuditEntry(SQLModel, table=True):
    """
    Compliance audit log for PII operations.

    Satisfies:
    - HIPAA §164.312(b) - Audit controls
    - SOC 2 CC7.2 - System monitoring
    """

    __tablename__: ClassVar[str] = "pii_audit_log"

    id: int | None = Field(default=None, primary_key=True)
    event_id: str = Field(unique=True, index=True)  # UUID for correlation
    timestamp: datetime = Field(default_factory=utc_now, index=True)
    event_type: str = Field(index=True)  # PIIEventType value

    # Actor information
    user_id: str | None = Field(default=None, index=True)
    session_id: str | None = Field(default=None, index=True)
    agent_id: str | None = Field(default=None, index=True)
    source_ip: str | None = None

    # Resource information
    placeholder: str | None = None  # e.g., "<PERSON_1>"
    pii_type: str | None = None  # e.g., "PERSON", "SSN"
    data_classification: str = Field(default="confidential")

    # Outcome
    success: bool = True
    error_message: str | None = None

    # Compliance metadata
    encryption_key_id: str | None = None
    integrity_hash: str | None = None  # For chain verification
    previous_hash: str | None = None  # Chain of custody
    metadata_json: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))


class PIIAuditEntryCreate(SQLModel):
    """Schema for creating PII audit entries."""

    event_id: str
    event_type: str
    user_id: str | None = None
    session_id: str | None = None
    agent_id: str | None = None
    source_ip: str | None = None
    placeholder: str | None = None
    pii_type: str | None = None
    data_classification: str = "confidential"
    success: bool = True
    error_message: str | None = None
    encryption_key_id: str | None = None
    integrity_hash: str | None = None
    previous_hash: str | None = None
    metadata_json: dict[str, Any] | None = None


class PIIAuditEntryRead(SQLModel):
    """Schema for reading PII audit entries."""

    id: int
    event_id: str
    timestamp: datetime
    event_type: str
    user_id: str | None
    session_id: str | None
    placeholder: str | None
    pii_type: str | None
    success: bool
    error_message: str | None


class PIISession(SQLModel, table=True):
    """
    Tracks PII sessions for compliance reporting.

    Links PII operations to user sessions for minimum necessary access auditing.
    """

    __tablename__: ClassVar[str] = "pii_sessions"

    id: int | None = Field(default=None, primary_key=True)
    session_id: str = Field(unique=True, index=True)
    user_id: str = Field(index=True)
    created_at: datetime = Field(default_factory=utc_now, index=True)
    expires_at: datetime | None = None
    is_active: bool = Field(default=True)

    # Statistics
    store_count: int = Field(default=0)
    retrieve_count: int = Field(default=0)
    last_activity_at: datetime | None = None

    # Metadata
    agent_id: str | None = None
    purpose: str | None = None  # For minimum necessary documentation
    tenant_id: str = Field(default="default", index=True, max_length=128)
    principal_id: str | None = Field(default=None, index=True, max_length=64)
    channel_id: str | None = Field(default=None, index=True, max_length=120)
    conversation_id: str | None = Field(default=None, index=True, max_length=255)
    obligation_profile: str = Field(default="strict_tokenized", max_length=64)
    authorized_viewers: list[str] = Field(
        default_factory=list, sa_column=Column(JSON, nullable=False)
    )
    metadata_json: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))


class PIISessionCreate(SQLModel):
    """Schema for creating PII sessions."""

    session_id: str
    user_id: str
    agent_id: str | None = None
    purpose: str | None = None
    expires_at: datetime | None = None
    channel_id: str | None = None
    conversation_id: str | None = None
    obligation_profile: str = "strict_tokenized"
    authorized_viewers: list[str] = Field(default_factory=list)


class PIISessionRead(SQLModel):
    """Schema for reading PII sessions."""

    id: int
    session_id: str
    user_id: str
    created_at: datetime
    expires_at: datetime | None
    is_active: bool
    store_count: int
    retrieve_count: int
    last_activity_at: datetime | None
    tenant_id: str
    principal_id: str | None
    channel_id: str | None
    conversation_id: str | None
    obligation_profile: str
    authorized_viewers: list[str]


# PIIPermission is now imported from common_enums at the top of this module
# to maintain single source of truth across the codebase


class PIIHumanMapping(SQLModel, table=True):
    """Human-side canonical PII storage for a session-scoped token lifecycle."""

    __tablename__: ClassVar[str] = "pii_human_mappings"
    __table_args__ = (
        UniqueConstraint(
            "session_id",
            "normalized_value_hash",
            name="uq_pii_human_session_value",
        ),
    )

    id: int | None = Field(default=None, primary_key=True)
    session_id: str = Field(index=True)
    owner_user_id: int | None = Field(default=None, foreign_key="users.id", index=True)
    owner_user_email: str | None = Field(default=None, index=True)
    pii_type: str = Field(index=True)
    normalized_value_hash: str = Field(index=True, max_length=128)
    ciphertext: str
    encryption_key_id: str = Field(index=True, max_length=128)
    integrity_hash: str = Field(max_length=256)
    created_at: datetime = Field(default_factory=utc_now, index=True)
    expires_at: datetime | None = Field(default=None, index=True)
    access_count: int = Field(default=0)
    last_accessed_at: datetime | None = None


class PIIAIConversationToken(SQLModel, table=True):
    """AI-facing synthetic token references mapped to human-side PII rows."""

    __tablename__: ClassVar[str] = "pii_ai_tokens"
    __table_args__ = (
        UniqueConstraint("session_id", "token", name="uq_pii_ai_session_token"),
        UniqueConstraint(
            "session_id",
            "human_mapping_id",
            name="uq_pii_ai_session_human_mapping",
        ),
    )

    id: int | None = Field(default=None, primary_key=True)
    session_id: str = Field(index=True)
    owner_user_id: int | None = Field(default=None, foreign_key="users.id", index=True)
    owner_user_email: str | None = Field(default=None, index=True)
    token: str = Field(index=True, max_length=128)
    pii_type: str = Field(index=True)
    human_mapping_id: int = Field(foreign_key="pii_human_mappings.id", index=True)
    created_at: datetime = Field(default_factory=utc_now, index=True)
    expires_at: datetime | None = Field(default=None, index=True)
    access_count: int = Field(default=0)
    last_accessed_at: datetime | None = None


class UserPIIPermissions(SQLModel, table=True):
    """
    Maps users to PII-specific permissions.

    Extends the basic role system with granular PII permissions
    for SOC 2 CC6.1 compliance.
    """

    __tablename__: ClassVar[str] = "user_pii_permissions"

    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id", index=True)
    permission: str  # PIIPermission value
    granted_by: int | None = Field(default=None, foreign_key="users.id")
    granted_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = None
    reason: str | None = None  # Justification for access


class UserPIIPermissionCreate(SQLModel):
    """Schema for granting PII permissions."""

    user_id: int
    permission: str
    reason: str | None = None
    expires_at: datetime | None = None


class UserPIIPermissionRead(SQLModel):
    """Schema for reading PII permissions."""

    id: int
    user_id: int
    permission: str
    granted_by: int | None
    granted_at: datetime
    expires_at: datetime | None
    reason: str | None


class EncryptionKeyRecord(SQLModel, table=True):
    """
    Tracks encryption key metadata (not the keys themselves).

    For HIPAA §164.312(a)(2)(iv) - Encryption key management.
    """

    __tablename__: ClassVar[str] = "encryption_keys"

    id: int | None = Field(default=None, primary_key=True)
    key_id: str = Field(unique=True, index=True)  # UUID identifier
    algorithm: str = Field(default="AES-256-GCM")
    created_at: datetime = Field(default_factory=utc_now)
    rotated_at: datetime | None = None
    expires_at: datetime | None = None
    is_active: bool = Field(default=True)
    created_by: int | None = Field(default=None, foreign_key="users.id")

    # Key status
    usage_count: int = Field(default=0)
    last_used_at: datetime | None = None


class EncryptionKeyRecordRead(SQLModel):
    """Schema for reading encryption key metadata."""

    id: int
    key_id: str
    algorithm: str
    created_at: datetime
    rotated_at: datetime | None
    is_active: bool
    usage_count: int
    last_used_at: datetime | None


# ============== Compliance Reports ==============


class PIIComplianceStats(SQLModel):
    """Statistics for compliance dashboard."""

    total_pii_stored: int
    total_pii_retrieved: int
    total_sessions: int
    active_sessions: int
    integrity_failures: int
    access_denied_count: int
    encryption_key_age_days: int
    last_key_rotation: datetime | None


class PIIAccessReport(SQLModel):
    """Access report for HIPAA auditing."""

    user_id: str
    session_id: str
    access_count: int
    pii_types_accessed: list[str]
    first_access: datetime
    last_access: datetime
    purposes: list[str]
