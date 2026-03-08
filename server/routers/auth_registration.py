"""Registration, password, session lifecycle, and token endpoints.

Extracted from auth.py to satisfy REQ-MOD-01 (800-line module limit).
All routes are mounted as a sub-router on the parent auth router.
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import desc, not_
from sqlmodel import SQLModel, col, select

from .auth_utils import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    create_access_token,
    get_password_hash,
    verify_password,
)
from .auth import get_current_user, require_admin
from .result_utils import result_all, result_one_or_none
from ..audit import emit_audit_event
from ..models import (
    SessionAssuranceLevel,
    User,
    UserCreate,
    UserRead,
    UserSession,
    UserSessionRead,
    get_session,
    RefreshToken,
)
from ..security.identity import (
    ensure_user_identity_records,
    get_principal_risk,
    get_roles_for_principal,
    local_password_auth_allowed,
    normalize_role,
)
from ..utils.db import (
    execute as db_execute,
    commit as db_commit,
    refresh as db_refresh,
    get as db_get,
)

router = APIRouter(tags=["auth"])
limiter = Limiter(key_func=get_remote_address)


# ------------------------------------------------------------------
# Rate-limit configuration (mirrors auth.py)
# ------------------------------------------------------------------

_ENV = os.getenv("AGENTGATE_ENV", "development")
_TESTING = _ENV == "test" or os.getenv("TESTING") == "true"
RATE_LIMIT_STRICT = "10000/minute" if _TESTING else "5/minute"
RATE_LIMIT_NORMAL = "10000/minute" if _TESTING else "10/minute"


# ------------------------------------------------------------------
# Registration
# ------------------------------------------------------------------


@router.post("/register", response_model=UserRead)
@limiter.limit(RATE_LIMIT_STRICT)
async def register(
    request: Request,
    user_data: UserCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Register a new user."""
    _ = request  # Used for rate limiting only
    if not local_password_auth_allowed():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Local signup is disabled for this "
                "deployment. Use external identity "
                "provider login."
            ),
        )

    # Check if user exists
    result = await db_execute(
        session,
        select(User).where(
            User.email == user_data.email,
        ),
    )
    existing = result_one_or_none(result)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    # Create as viewer first, then promote based on persisted
    # first-user ordering. This avoids a TOCTOU race where
    # concurrent registrations both observe an empty users table
    # and both grant themselves admin.
    hashed_pw = await get_password_hash(user_data.password)
    user = User(
        email=user_data.email,
        name=user_data.name,
        hashed_password=hashed_pw,
        role="viewer",
        identity_provider="local",
        tenant_id="default",
    )
    session.add(user)
    await db_commit(session)
    await db_refresh(session, user)

    first_user_result = await db_execute(
        session,
        select(col(User.id)).order_by(col(User.id)).limit(1),
    )
    first_user_id = result_one_or_none(first_user_result)
    if first_user_id == user.id:
        user.role = "admin"
        session.add(user)
        await db_commit(session)
        await db_refresh(session, user)

    await ensure_user_identity_records(
        session,
        user=user,
        provider="local",
        provider_subject=user.email,
        tenant_id=user.tenant_id or "default",
        roles=[user.role],
    )
    await db_commit(session)

    # Audit log
    await emit_audit_event(
        session,
        event_type="user_register",
        actor=user.email,
        result="success",
        details={"role": user.role},
    )
    await db_commit(session)

    return user


# ------------------------------------------------------------------
# Password management
# ------------------------------------------------------------------


class PasswordChangeRequest(SQLModel):
    """Request schema for changing password."""

    current_password: str
    new_password: str


@router.post("/password")
async def change_password(
    payload: PasswordChangeRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    """Change current user's password.

    Also clears must_change_password and
    is_default_credentials flags on success.
    """
    if not await verify_password(
        payload.current_password,
        current_user.hashed_password,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect current password",
        )

    current_user.hashed_password = await get_password_hash(
        payload.new_password,
    )
    current_user.must_change_password = False
    current_user.is_default_credentials = False
    current_user.password_changed_at = datetime.now(timezone.utc).replace(tzinfo=None)
    session.add(current_user)
    await db_commit(session)

    await emit_audit_event(
        session,
        event_type="password_changed",
        actor=current_user.email,
        result="success",
        details={"cleared_default_credentials": True},
    )
    await db_commit(session)
    return {
        "status": "ok",
        "message": "Password changed successfully",
    }


# ------------------------------------------------------------------
# Session management
# ------------------------------------------------------------------


@router.get(
    "/sessions",
    response_model=list[UserSessionRead],
)
async def list_sessions(
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[UserSessionRead]:
    """List active sessions for current user."""
    result = await db_execute(
        session,
        select(UserSession)
        .where(UserSession.user_id == current_user.id)
        .where(not_(col(UserSession.revoked)))
        .order_by(desc(col(UserSession.last_active))),
    )
    sessions = result_all(result)
    current_session_id = sessions[0].session_id if sessions else None

    return [
        UserSessionRead(
            id=s.session_id,
            device=s.device or "Unknown",
            browser=s.browser or "Unknown",
            ip_address=s.ip_address,
            location=s.location or "Unknown",
            created_at=s.created_at,
            last_active=s.last_active,
            is_current=(s.session_id == current_session_id),
        )
        for s in sessions
    ]


@router.delete("/sessions/{session_id}")
async def revoke_session(
    session_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    """Revoke a specific session for current user."""
    result = await db_execute(
        session,
        select(UserSession).where(
            UserSession.session_id == session_id,
            UserSession.user_id == current_user.id,
        ),
    )
    session_record = result_one_or_none(result)
    if not session_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found",
        )

    session_record.revoked = True
    session_record.revoked_at = datetime.now(timezone.utc).replace(tzinfo=None)
    session.add(session_record)

    # Revoke refresh token if present
    if session_record.refresh_token:
        token_result = await db_execute(
            session,
            select(RefreshToken).where(
                RefreshToken.token == session_record.refresh_token,
            ),
        )
        token_record = result_one_or_none(token_result)
        if token_record:
            token_record.revoked = True
            token_record.revoked_at = datetime.now(timezone.utc).replace(
                tzinfo=None,
            )
            session.add(token_record)

    await db_commit(session)
    return {"status": "revoked"}


@router.delete("/sessions")
async def revoke_other_sessions(
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    """Revoke all sessions except the most recently active."""
    result = await db_execute(
        session,
        select(UserSession)
        .where(UserSession.user_id == current_user.id)
        .where(not_(col(UserSession.revoked)))
        .order_by(desc(col(UserSession.last_active))),
    )
    sessions = result_all(result)
    if not sessions:
        return {"status": "ok", "revoked": 0}

    revoked_count = 0

    for record in sessions[1:]:
        record.revoked = True
        record.revoked_at = datetime.now(timezone.utc).replace(tzinfo=None)
        session.add(record)
        revoked_count += 1

        if record.refresh_token:
            token_result = await db_execute(
                session,
                select(RefreshToken).where(
                    RefreshToken.token == record.refresh_token,
                ),
            )
            token_record = result_one_or_none(
                token_result,
            )
            if token_record:
                token_record.revoked = True
                token_record.revoked_at = datetime.now(timezone.utc).replace(
                    tzinfo=None,
                )
                session.add(token_record)

    await db_commit(session)
    return {"status": "ok", "revoked": revoked_count}


# ------------------------------------------------------------------
# MFA status check
# ------------------------------------------------------------------


class CheckMFARequest(SQLModel):
    """Request schema for checking MFA status."""

    email: str


@router.post("/check-mfa")
async def check_mfa_status(
    request: CheckMFARequest,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    """Check if an email has MFA enabled.

    Useful for client to know whether to show MFA field.

    Args:
        request: Request payload with email address.

    Returns:
        Dictionary with mfa_enabled boolean.
    """
    result = await db_execute(
        session,
        select(User).where(User.email == request.email),
    )
    user = result_one_or_none(result)

    if not user:
        # Don't reveal if user exists
        return {"mfa_enabled": False}

    return {"mfa_enabled": user.totp_enabled}


# ------------------------------------------------------------------
# Token refresh and revocation
# ------------------------------------------------------------------


class RefreshRequest(SQLModel):
    """Request schema for token refresh."""

    refresh_token: str


@router.post("/refresh")
@limiter.limit(RATE_LIMIT_NORMAL)
async def refresh_access_token(
    request: Request,
    refresh_request: RefreshRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Exchange refresh token for new access token.

    Rate limit: 10 requests per minute.

    Returns:
        New access token with same expiration as login.
    """
    _ = request  # Used for rate limiting only
    # Look up refresh token
    result = await db_execute(
        session,
        select(RefreshToken).where(
            RefreshToken.token == refresh_request.refresh_token,
        ),
    )
    token_record = result_one_or_none(result)

    # Validate token exists
    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    # Check if revoked
    if token_record.revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked",
        )

    # Check if expired (strip tz for safe comparison)
    expires_at = token_record.expires_at
    if expires_at.tzinfo is not None:
        expires_at = expires_at.replace(tzinfo=None)
    now_naive = datetime.now(timezone.utc).replace(tzinfo=None)
    if expires_at < now_naive:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired",
        )

    # Get user
    user = await db_get(
        session,
        User,
        token_record.user_id,
    )
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    # Create new access token
    principal_risk = await get_principal_risk(
        session,
        principal_id=user.principal_id,
        fallback_role=user.role,
    )
    roles = await get_roles_for_principal(
        session,
        principal_id=user.principal_id,
        tenant_id=user.tenant_id or "default",
        fallback_role=user.role,
    )
    access_token = create_access_token(
        data={
            "sub": user.email,
            "email": user.email,
            "name": user.name,
            "role": normalize_role(user.role),
            "roles": roles,
            "provider": (user.identity_provider or "local"),
            "provider_subject": (user.provider_subject),
            "tenant_id": user.tenant_id or "default",
            "session_assurance": (SessionAssuranceLevel.A1.value),
            "principal_risk": principal_risk,
        },
        expires_delta=timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES,
        ),
    )

    # Update session last_active for the refresh token
    session_result = await db_execute(
        session,
        select(UserSession).where(
            UserSession.refresh_token == refresh_request.refresh_token,
        ),
    )
    session_record = result_one_or_none(session_result)
    if session_record:
        session_record.last_active = datetime.now(timezone.utc).replace(
            tzinfo=None,
        )
        session.add(session_record)

    # Audit log
    await emit_audit_event(
        session,
        event_type="token_refresh",
        actor=user.email,
        result="success",
        details={
            "method": "refresh_token",
            "role": user.role,
        },
    )
    await db_commit(session)

    return {
        "access_token": access_token,
        "token_type": "bearer",  # nosec B105
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }


@router.post("/revoke")
async def revoke_refresh_token(
    refresh_request: RefreshRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Revoke a refresh token (logout).

    Requires authentication to prevent token enumeration.
    """
    # Look up token
    result = await db_execute(
        session,
        select(RefreshToken).where(
            RefreshToken.token == refresh_request.refresh_token,
            RefreshToken.user_id == current_user.id,
        ),
    )
    token_record = result_one_or_none(result)

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Refresh token not found",
        )

    # Revoke token
    token_record.revoked = True
    token_record.revoked_at = datetime.now(timezone.utc).replace(tzinfo=None)
    session.add(token_record)

    # Revoke associated session
    session_result = await db_execute(
        session,
        select(UserSession).where(
            UserSession.refresh_token == refresh_request.refresh_token,
        ),
    )
    session_record = result_one_or_none(session_result)
    if session_record:
        session_record.revoked = True
        session_record.revoked_at = datetime.now(timezone.utc).replace(
            tzinfo=None,
        )
        session.add(session_record)

    # Audit log
    await emit_audit_event(
        session,
        event_type="token_revoke",
        actor=current_user.email,
        result="success",
    )
    await db_commit(session)

    return {"status": "revoked"}


# ------------------------------------------------------------------
# Admin session revocation
# ------------------------------------------------------------------


@router.post(
    "/admin/revoke-user-sessions/{user_id}",
)
async def admin_revoke_user_sessions(
    user_id: int,
    _current_user: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Admin: revoke all tokens and sessions for a user.

    Forces the target user to re-authenticate by revoking
    every active refresh token and session record.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    tokens_revoked = 0
    sessions_revoked = 0

    token_result = await db_execute(
        session,
        select(RefreshToken).where(
            RefreshToken.user_id == user_id,
            not_(col(RefreshToken.revoked)),
        ),
    )
    for token_record in result_all(token_result):
        token_record.revoked = True
        token_record.revoked_at = now
        session.add(token_record)
        tokens_revoked += 1

    session_result = await db_execute(
        session,
        select(UserSession).where(
            UserSession.user_id == user_id,
            not_(col(UserSession.revoked)),
        ),
    )
    for session_record in result_all(session_result):
        session_record.revoked = True
        session_record.revoked_at = now
        session.add(session_record)
        sessions_revoked += 1

    await emit_audit_event(
        session,
        event_type="admin_revoke_user_sessions",
        actor=_current_user.email,
        result="success",
        details={
            "target_user_id": user_id,
            "tokens_revoked": tokens_revoked,
            "sessions_revoked": sessions_revoked,
        },
    )
    await db_commit(session)

    return {
        "status": "revoked",
        "user_id": user_id,
        "tokens_revoked": tokens_revoked,
        "sessions_revoked": sessions_revoked,
    }
