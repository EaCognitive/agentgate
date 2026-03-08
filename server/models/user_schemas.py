"""User and authentication-related schemas and models."""

from datetime import datetime, timezone
from enum import Enum
from typing import ClassVar

from sqlmodel import SQLModel, Field
from sqlalchemy import Column, JSON


def utc_now() -> datetime:
    """Get current UTC time as timezone-naive (for TIMESTAMP WITHOUT TIME ZONE columns)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ============== User & Auth Enums ==============


class UserRole(str, Enum):
    """User roles with hierarchical permissions.

    Hierarchy (most to least privileged):
    - admin: Full system access, user management, configuration
    - security_admin: Security posture owner with policy and incident authority
    - approver: Can approve/deny sensitive execution requests
    - auditor: Read-only access to logs and compliance records
    - developer: Can create datasets, run tests, and inspect traces
    - agent_operator: Operational role for production agent workflows
    - service_agent: Programmatic least-privilege service identity
    - viewer: Restricted read-only access
    """

    ADMIN = "admin"
    SECURITY_ADMIN = "security_admin"
    APPROVER = "approver"
    AUDITOR = "auditor"
    DEVELOPER = "developer"
    AGENT_OPERATOR = "agent_operator"
    SERVICE_AGENT = "service_agent"
    VIEWER = "viewer"


class Permission(str, Enum):
    """Granular permissions for RBAC."""

    # User management
    USER_CREATE = "user:create"
    USER_READ = "user:read"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"

    # Trace management
    TRACE_READ = "trace:read"
    TRACE_READ_ALL = "trace:read_all"
    TRACE_DELETE = "trace:delete"

    # Approval management
    APPROVAL_READ = "approval:read"
    APPROVAL_DECIDE = "approval:decide"

    # Audit logs
    AUDIT_READ = "audit:read"
    AUDIT_EXPORT = "audit:export"

    # Dataset management
    DATASET_CREATE = "dataset:create"
    DATASET_READ = "dataset:read"
    DATASET_UPDATE = "dataset:update"
    DATASET_DELETE = "dataset:delete"
    DATASET_RUN = "dataset:run"

    # Cost management
    COST_READ = "cost:read"
    COST_WRITE = "cost:write"
    COST_LIMIT = "cost:limit"

    # System configuration
    CONFIG_READ = "config:read"
    CONFIG_UPDATE = "config:update"
    # Security threats
    SECURITY_THREAT_READ = "security_threat:read"
    SECURITY_THREAT_UPDATE = "security_threat:update"


# Role to permissions mapping
ROLE_PERMISSIONS: dict[str, list[Permission]] = {
    "admin": [
        # All permissions
        Permission.USER_CREATE,
        Permission.USER_READ,
        Permission.USER_UPDATE,
        Permission.USER_DELETE,
        Permission.TRACE_READ,
        Permission.TRACE_READ_ALL,
        Permission.TRACE_DELETE,
        Permission.APPROVAL_READ,
        Permission.APPROVAL_DECIDE,
        Permission.AUDIT_READ,
        Permission.AUDIT_EXPORT,
        Permission.DATASET_CREATE,
        Permission.DATASET_READ,
        Permission.DATASET_UPDATE,
        Permission.DATASET_DELETE,
        Permission.DATASET_RUN,
        Permission.COST_READ,
        Permission.COST_WRITE,
        Permission.COST_LIMIT,
        Permission.CONFIG_READ,
        Permission.CONFIG_UPDATE,
        Permission.SECURITY_THREAT_READ,
        Permission.SECURITY_THREAT_UPDATE,
    ],
    "security_admin": [
        Permission.USER_READ,
        Permission.USER_UPDATE,
        Permission.TRACE_READ_ALL,
        Permission.APPROVAL_READ,
        Permission.APPROVAL_DECIDE,
        Permission.AUDIT_READ,
        Permission.AUDIT_EXPORT,
        Permission.DATASET_READ,
        Permission.COST_READ,
        Permission.CONFIG_READ,
        Permission.CONFIG_UPDATE,
        Permission.SECURITY_THREAT_READ,
        Permission.SECURITY_THREAT_UPDATE,
    ],
    "approver": [
        Permission.USER_READ,
        Permission.TRACE_READ_ALL,
        Permission.APPROVAL_READ,
        Permission.APPROVAL_DECIDE,
        Permission.AUDIT_READ,
        Permission.DATASET_READ,
        Permission.COST_READ,
        Permission.SECURITY_THREAT_READ,
    ],
    "auditor": [
        Permission.USER_READ,
        Permission.TRACE_READ_ALL,
        Permission.APPROVAL_READ,
        Permission.AUDIT_READ,
        Permission.AUDIT_EXPORT,
        Permission.DATASET_READ,
        Permission.COST_READ,
        Permission.CONFIG_READ,
        Permission.SECURITY_THREAT_READ,
    ],
    "developer": [
        Permission.USER_READ,
        Permission.TRACE_READ,
        Permission.TRACE_READ_ALL,
        Permission.APPROVAL_READ,
        Permission.DATASET_CREATE,
        Permission.DATASET_READ,
        Permission.DATASET_UPDATE,
        Permission.DATASET_DELETE,
        Permission.DATASET_RUN,
        Permission.COST_READ,
        Permission.COST_WRITE,
        Permission.SECURITY_THREAT_READ,
    ],
    "agent_operator": [
        Permission.USER_READ,
        Permission.TRACE_READ,
        Permission.TRACE_READ_ALL,
        Permission.APPROVAL_READ,
        Permission.DATASET_READ,
        Permission.DATASET_RUN,
        Permission.COST_READ,
        Permission.SECURITY_THREAT_READ,
    ],
    "service_agent": [
        Permission.TRACE_READ,
        Permission.DATASET_READ,
        Permission.DATASET_RUN,
        Permission.SECURITY_THREAT_READ,
    ],
    "viewer": [
        Permission.USER_READ,
        Permission.TRACE_READ,
        Permission.APPROVAL_READ,
        Permission.DATASET_READ,
        Permission.COST_READ,
        Permission.SECURITY_THREAT_READ,
    ],
}

# Backward-compatible alias during the role migration window.
ROLE_PERMISSIONS["operator"] = ROLE_PERMISSIONS["approver"]


# ============== User Models ==============


class UserBase(SQLModel):
    """Base schema with common user fields for create and read operations."""

    email: str = Field(unique=True, index=True, max_length=255)
    name: str | None = Field(default=None, max_length=255)
    role: str = Field(default="viewer", max_length=50)


class User(UserBase, table=True):
    """Database model for user accounts with authentication and MFA support."""

    __tablename__: ClassVar[str] = "users"

    id: int | None = Field(default=None, primary_key=True)
    hashed_password: str = Field(max_length=255)
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=utc_now)
    last_login: datetime | None = None

    # Security enforcement
    must_change_password: bool = Field(default=False)
    password_changed_at: datetime | None = None
    is_default_credentials: bool = Field(default=False)

    # Failed login tracking for CAPTCHA
    failed_login_attempts: int = Field(default=0)
    last_failed_login: datetime | None = None

    # MFA fields
    totp_secret: str | None = Field(default=None)  # Encrypted TOTP secret
    totp_enabled: bool = Field(default=False)  # Whether MFA is enabled
    backup_codes: list[str] | None = Field(
        default=None, sa_column=Column(JSON)
    )  # Emergency backup codes

    # WebAuthn/Passkey fields
    webauthn_credentials: list[dict] | None = Field(default=None, sa_column=Column(JSON))
    # Each credential: {
    #   "credential_id": str,  # Base64 encoded
    #   "public_key": str,     # Base64 encoded
    #   "sign_count": int,
    #   "transports": list[str],  # ["usb", "nfc", "ble", "internal"]
    #   "created_at": str,
    #   "last_used": str,
    #   "name": str  # User-friendly name like "MacBook Touch ID"
    # }

    # Identity provider linkage for external IdP migration paths.
    principal_id: str | None = Field(default=None, index=True, max_length=64)
    identity_provider: str = Field(default="local", index=True, max_length=64)
    provider_subject: str | None = Field(default=None, index=True, max_length=255)
    tenant_id: str = Field(default="default", index=True, max_length=128)


class RefreshToken(SQLModel, table=True):
    """Refresh tokens for JWT authentication.

    Allows issuing new access tokens without re-authentication.
    Tokens are revocable for security.
    """

    __tablename__: ClassVar[str] = "refresh_tokens"

    id: int | None = Field(default=None, primary_key=True)
    token: str = Field(unique=True, index=True, max_length=512)
    user_id: int = Field(foreign_key="users.id", index=True)
    expires_at: datetime = Field(index=True)
    created_at: datetime = Field(default_factory=utc_now)
    revoked: bool = Field(default=False, index=True)
    revoked_at: datetime | None = None


class UserCreate(SQLModel):
    """Schema for creating new user accounts with validation."""

    email: str = Field(max_length=255, min_length=3)
    password: str = Field(max_length=128, min_length=8)
    name: str | None = Field(default=None, max_length=255)


class UserRead(UserBase):
    """Schema for reading user information from API endpoints."""

    id: int
    is_active: bool
    created_at: datetime
    totp_enabled: bool


# ============== User Sessions ==============


class UserSession(SQLModel, table=True):
    """Database model for user session tracking with device and geo information."""

    __tablename__: ClassVar[str] = "user_sessions"

    id: int | None = Field(default=None, primary_key=True)
    session_id: str = Field(index=True, unique=True, max_length=64)
    user_id: int = Field(foreign_key="users.id", index=True)
    refresh_token: str | None = Field(default=None, index=True, max_length=512)
    ip_address: str | None = Field(default=None, max_length=64)
    user_agent: str | None = Field(default=None, max_length=512)
    device: str | None = Field(default="Unknown", max_length=128)
    browser: str | None = Field(default="Unknown", max_length=128)
    location: str | None = Field(default="Unknown", max_length=128)
    created_at: datetime = Field(default_factory=utc_now, index=True)
    last_active: datetime = Field(default_factory=utc_now, index=True)
    revoked: bool = Field(default=False, index=True)
    revoked_at: datetime | None = None


class UserSessionRead(SQLModel):
    """Schema for reading user session information from API endpoints."""

    id: str
    device: str
    browser: str
    ip_address: str | None
    location: str
    created_at: datetime
    last_active: datetime
    is_current: bool
