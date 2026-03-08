"""API Key management for service-to-service and MCP authentication.

Provides secure API key generation, validation, and revocation.
API keys are hashed before storage (like passwords) for security.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from sqlmodel import select, Field, SQLModel

from ..audit import emit_audit_event
from ..models import ROLE_PERMISSIONS, User, get_session
from ..security.identity import normalize_role
from ..utils.db import execute as db_execute, commit as db_commit, refresh as db_refresh
from .auth import get_current_user, require_admin

router = APIRouter(prefix="/auth/api-keys", tags=["api-keys"])


class APIKey(SQLModel, table=True):
    """API key for service authentication."""

    __tablename__: str = "api_keys"  # type: ignore[assignment]

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(max_length=128, index=True)
    key_hash: str = Field(max_length=128)  # SHA-256 hash of the key
    key_prefix: str = Field(max_length=12)  # First 8 chars for identification
    user_id: int = Field(foreign_key="users.id", index=True)
    scopes: str = Field(default="*")  # Comma-separated scopes or "*" for full access
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc).replace(tzinfo=None)
    )
    last_used_at: datetime | None = Field(default=None)
    expires_at: datetime | None = Field(default=None)
    revoked: bool = Field(default=False)
    revoked_at: datetime | None = Field(default=None)


class APIKeyCreate(SQLModel):
    """Request to create a new API key."""

    name: str = Field(min_length=1, max_length=128)
    scopes: str = Field(default="*", max_length=1024)
    expires_in_days: int | None = Field(default=None, ge=1, le=365)


class APIKeyResponse(SQLModel):
    """Response after creating an API key (includes the actual key - shown only once)."""

    id: int
    name: str
    key: str  # Only returned on creation
    key_prefix: str
    scopes: str
    created_at: datetime
    expires_at: datetime | None
    message: str


class APIKeyListItem(SQLModel):
    """API key info for listing (no actual key)."""

    id: int
    name: str
    key_prefix: str
    scopes: str
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime | None
    revoked: bool


class APIKeyScopeCapabilities(SQLModel):
    """Scope governance details for the current user's API key privileges."""

    role: str
    wildcard_allowed: bool
    allowed_scopes: list[str]
    required_for_admin_mcp: list[str]


def _parse_csv_items(value: str) -> list[str]:
    return [item.strip().lower() for item in value.split(",") if item.strip()]


def _parse_scopes(raw_scopes: str) -> list[str]:
    scopes = raw_scopes.strip()
    if scopes == "*":
        return ["*"]
    parsed = sorted(set(_parse_csv_items(scopes)))
    if parsed:
        return parsed
    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail=(
            "At least one explicit scope is required. "
            "Use comma-separated scopes (for example: 'dataset:read,trace:read')."
        ),
    )


def _wildcard_allowed_roles() -> set[str]:
    configured = os.getenv("API_KEY_WILDCARD_ROLES", "admin,security_admin")
    parsed = {normalize_role(role) for role in _parse_csv_items(configured)}
    parsed.discard("")
    return parsed or {"admin"}


def _mcp_scope_roles() -> set[str]:
    configured = os.getenv("API_KEY_MCP_SCOPE_ROLES", "admin,security_admin,developer")
    parsed = {normalize_role(role) for role in _parse_csv_items(configured)}
    parsed.discard("")
    return parsed or {"admin", "security_admin", "developer"}


def _allowed_custom_scopes() -> set[str]:
    configured = os.getenv(
        "API_KEY_ALLOWED_CUSTOM_SCOPES",
        "mcp:read,mcp:write,mcp:access,mcp:admin",
    )
    parsed = set(_parse_csv_items(configured))
    if parsed:
        return parsed
    return {"mcp:read", "mcp:write", "mcp:access", "mcp:admin"}


def _allowed_scopes_for_role(role: str) -> set[str]:
    normalized_role = normalize_role(role)
    permission_scopes = {
        permission.value for permission in ROLE_PERMISSIONS.get(normalized_role, [])
    }
    if normalized_role not in _mcp_scope_roles():
        return permission_scopes

    allowed_custom = _allowed_custom_scopes()
    if normalized_role not in _wildcard_allowed_roles():
        allowed_custom = {scope for scope in allowed_custom if scope != "mcp:admin"}
    return permission_scopes.union(allowed_custom)


def _validate_requested_scopes(raw_scopes: str, role: str) -> str:
    requested = _parse_scopes(raw_scopes)
    normalized_role = normalize_role(role)
    wildcard_roles = _wildcard_allowed_roles()

    if requested == ["*"]:
        if normalized_role not in wildcard_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "Wildcard API-key scope is restricted to privileged roles. "
                    "Request explicit least-privilege scopes."
                ),
            )
        return "*"

    allowed_scopes = _allowed_scopes_for_role(normalized_role)
    denied_scopes = sorted(scope for scope in requested if scope not in allowed_scopes)
    if denied_scopes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "message": "Requested scopes exceed role permissions",
                "denied_scopes": denied_scopes,
                "role": normalized_role,
            },
        )
    return ",".join(requested)


def generate_api_key() -> tuple[str, str, str]:
    """Generate a new API key.

    Returns:
        Tuple of (full_key, key_hash, key_prefix)
    """
    # Generate a 32-byte random key and encode as hex (64 chars)
    key_bytes = secrets.token_bytes(32)
    full_key = f"ag_{key_bytes.hex()}"  # ag_ prefix for identification

    # Hash the key for storage
    key_hash = hashlib.sha256(full_key.encode()).hexdigest()

    # Store prefix for identification
    key_prefix = full_key[:12]

    return full_key, key_hash, key_prefix


def hash_api_key(key: str) -> str:
    """Hash an API key for comparison."""
    return hashlib.sha256(key.encode()).hexdigest()


async def validate_api_key(
    key: str,
    session: AsyncSession,
) -> APIKey | None:
    """Validate an API key and return the key record if valid.

    Args:
        key: The full API key string
        session: Database session

    Returns:
        APIKey record if valid, None otherwise
    """
    key_hash = hash_api_key(key)

    result = await db_execute(
        session,
        select(APIKey).where(
            APIKey.key_hash == key_hash,
            text("revoked = false"),
        ),
    )
    api_key = result.scalar_one_or_none()

    if not api_key:
        return None

    # Check expiration
    if api_key.expires_at:
        now = datetime.now(timezone.utc)
        expires_at = api_key.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < now:
            return None

    # Update last used timestamp
    api_key.last_used_at = datetime.now(timezone.utc).replace(tzinfo=None)
    session.add(api_key)
    await db_commit(session)

    return api_key


@router.get("/capabilities", response_model=APIKeyScopeCapabilities)
async def get_api_key_scope_capabilities(
    current_user: Annotated[User, Depends(get_current_user)],
) -> APIKeyScopeCapabilities:
    """Return scope governance capabilities for current user role."""
    normalized_role = normalize_role(current_user.role)
    allowed_scopes = sorted(_allowed_scopes_for_role(normalized_role))
    return APIKeyScopeCapabilities(
        role=normalized_role,
        wildcard_allowed=normalized_role in _wildcard_allowed_roles(),
        allowed_scopes=allowed_scopes,
        required_for_admin_mcp=sorted({"mcp:admin", "mcp:access"}),
    )


@router.post("", response_model=APIKeyResponse)
async def create_api_key(
    request: APIKeyCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> APIKeyResponse:
    """Create a new API key for the current user.

    The full key is only returned once - store it securely.
    """
    if current_user.id is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User ID not available",
        )
    normalized_scopes = _validate_requested_scopes(request.scopes, current_user.role)

    # Generate key
    full_key, key_hash, key_prefix = generate_api_key()

    # Calculate expiration if specified
    expires_at = None
    if request.expires_in_days:
        expires_at = (datetime.now(timezone.utc) + timedelta(days=request.expires_in_days)).replace(
            tzinfo=None
        )

    # Create record
    api_key = APIKey(
        name=request.name,
        key_hash=key_hash,
        key_prefix=key_prefix,
        user_id=current_user.id,
        scopes=normalized_scopes,
        expires_at=expires_at,
    )
    session.add(api_key)
    await db_commit(session)
    await db_refresh(session, api_key)

    # Audit log
    await emit_audit_event(
        session,
        event_type="api_key_created",
        actor=current_user.email,
        result="success",
        details={
            "key_name": request.name,
            "key_prefix": key_prefix,
            "scopes": normalized_scopes,
        },
    )
    await db_commit(session)

    return APIKeyResponse(
        id=api_key.id,  # type: ignore[arg-type]
        name=api_key.name,
        key=full_key,
        key_prefix=key_prefix,
        scopes=normalized_scopes,
        created_at=api_key.created_at,
        expires_at=api_key.expires_at,
        message="Store this key securely - it will not be shown again!",
    )


@router.get("", response_model=list[APIKeyListItem])
async def list_api_keys(
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[APIKeyListItem]:
    """List all API keys for the current user."""
    if current_user.id is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User ID not available",
        )

    result = await db_execute(
        session,
        select(APIKey).where(APIKey.user_id == current_user.id),
    )
    keys = result.scalars().all()

    return [
        APIKeyListItem(
            id=k.id,  # type: ignore[arg-type]
            name=k.name,
            key_prefix=k.key_prefix,
            scopes=k.scopes,
            created_at=k.created_at,
            last_used_at=k.last_used_at,
            expires_at=k.expires_at,
            revoked=k.revoked,
        )
        for k in keys
    ]


@router.delete("/{key_id}")
async def revoke_api_key(
    key_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    """Revoke an API key."""
    result = await db_execute(
        session,
        select(APIKey).where(
            APIKey.id == key_id,
            APIKey.user_id == current_user.id,
        ),
    )
    api_key = result.scalar_one_or_none()

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )

    api_key.revoked = True
    api_key.revoked_at = datetime.now(timezone.utc).replace(tzinfo=None)
    session.add(api_key)

    # Audit log
    await emit_audit_event(
        session,
        event_type="api_key_revoked",
        actor=current_user.email,
        result="success",
        details={"key_name": api_key.name, "key_prefix": api_key.key_prefix},
    )
    await db_commit(session)

    return {"status": "revoked", "key_id": key_id}


# Admin endpoint to list all API keys
@router.get("/admin/all", response_model=list[APIKeyListItem])
async def list_all_api_keys(
    _admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    include_revoked: bool = False,
) -> list[APIKeyListItem]:
    """List all API keys in the system (admin only)."""
    query = select(APIKey)
    if not include_revoked:
        query = query.where(text("revoked = false"))

    result = await db_execute(session, query)
    keys = result.scalars().all()

    return [
        APIKeyListItem(
            id=k.id,  # type: ignore[arg-type]
            name=k.name,
            key_prefix=k.key_prefix,
            scopes=k.scopes,
            created_at=k.created_at,
            last_used_at=k.last_used_at,
            expires_at=k.expires_at,
            revoked=k.revoked,
        )
        for k in keys
    ]
