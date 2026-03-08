"""Shared authentication helper functions for token creation and login completion.

Centralizes common token handling logic used across auth and passkey routes.
"""

import os
from datetime import datetime, timezone, timedelta
from typing import Any, TypedDict

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import SQLModel, Field

from ..audit import emit_audit_event
from ..models import User, UserSession, UserRead
from ..security.identity import ensure_user_identity_records, normalize_role
from ..utils.db import commit as db_commit
from .auth_utils import (
    create_access_token,
    create_refresh_token,
    parse_user_agent,
    ACCESS_TOKEN_EXPIRE_MINUTES,
)


class LoginResponse(SQLModel):
    """Standard login response with tokens and user info."""

    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int
    user: UserRead
    must_change_password: bool = False
    security_warning: str | None = None
    auth_provider: str = "local"
    session_assurance: str = "A1"
    principal_risk: str = "R1"
    tenant_id: str = "default"
    roles: list[str] = Field(default_factory=list)
    scopes: list[str] = Field(default_factory=list)


class LoginCompletionOptions(TypedDict, total=False):
    """Optional inputs used to finalize a successful login."""

    user_agent: str | None
    ip_address: str | None
    access_token: str | None
    refresh_token: str | None
    auth_method: str
    provider: str
    provider_subject: str | None
    tenant_id: str
    roles: list[str] | None
    scopes: list[str] | None
    session_assurance: str
    principal_risk: str | None
    token_claims: dict[str, Any]


_LOGIN_OPTION_DEFAULTS: LoginCompletionOptions = {
    "user_agent": None,
    "ip_address": None,
    "access_token": None,
    "refresh_token": None,
    "auth_method": "password",
    "provider": "local",
    "provider_subject": None,
    "tenant_id": "default",
    "roles": None,
    "scopes": None,
    "session_assurance": "A1",
    "principal_risk": None,
    "token_claims": {},
}


def _normalize_scopes(scopes: list[str] | None) -> list[str]:
    """Normalize and de-duplicate scope values for JWT/session payloads."""
    if not scopes:
        return []
    normalized = {scope.strip().lower() for scope in scopes if scope and scope.strip()}
    return sorted(normalized)


def _parse_login_completion_options(
    options: LoginCompletionOptions | None,
    legacy_kwargs: dict[str, Any],
) -> LoginCompletionOptions:
    """Merge legacy kwargs into a structured login completion options object."""
    resolved: LoginCompletionOptions = dict(_LOGIN_OPTION_DEFAULTS)
    if options:
        resolved.update(options)
    option_fields = set(_LOGIN_OPTION_DEFAULTS)
    unknown_keys = set(legacy_kwargs) - option_fields
    if unknown_keys:
        names = ", ".join(sorted(unknown_keys))
        raise TypeError(f"Unsupported login completion option(s): {names}")
    resolved.update(legacy_kwargs)
    return resolved


def _canonical_roles(user: User, roles: list[str] | None) -> list[str]:
    """Normalize role claims for the login response and token payload."""
    return [normalize_role(role) for role in (roles or [user.role]) if role]


def _apply_login_identity(user: User, options: LoginCompletionOptions) -> None:
    """Persist normalized identity information on the user record."""
    canonical_roles = _canonical_roles(user, options["roles"])
    if canonical_roles:
        user.role = canonical_roles[0]
    user.identity_provider = options["provider"]
    user.provider_subject = options["provider_subject"]
    user.tenant_id = options["tenant_id"]
    user.last_login = datetime.now(timezone.utc).replace(tzinfo=None)


def _build_login_token_claims(
    user: User,
    options: LoginCompletionOptions,
    canonical_roles: list[str],
    canonical_scopes: list[str],
    principal_risk: str | None,
) -> dict[str, Any]:
    """Build token claims used when the login flow needs fresh tokens."""
    claims = {
        "role": user.role,
        "roles": canonical_roles or [user.role],
        "provider": options["provider"],
        "provider_subject": options["provider_subject"],
        "tenant_id": options["tenant_id"],
        "scopes": canonical_scopes,
        "session_assurance": options["session_assurance"],
        "principal_risk": principal_risk,
    }
    claims.update(options["token_claims"])
    return claims


async def _create_tracked_user_session(
    user: User,
    session: AsyncSession,
    options: LoginCompletionOptions,
    refresh_token: str,
) -> None:
    """Persist device-tracking session state when client context is available."""
    if options["user_agent"] is None and options["ip_address"] is None:
        return
    if user.id is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User ID not available",
        )

    device, browser = (None, None)
    if options["user_agent"]:
        device, browser = parse_user_agent(options["user_agent"])

    session.add(
        UserSession(
            session_id=os.urandom(16).hex(),
            user_id=user.id,
            refresh_token=refresh_token,
            ip_address=options["ip_address"],
            user_agent=options["user_agent"],
            device=device,
            browser=browser,
            location="Unknown",
            last_active=datetime.now(timezone.utc).replace(tzinfo=None),
        )
    )


def _build_security_warning(user: User) -> tuple[bool, str | None]:
    """Return the credential warning state for the login response."""
    must_change = bool(getattr(user, "must_change_password", False))
    is_default = bool(getattr(user, "is_default_credentials", False))
    if not (must_change or is_default):
        return False, None
    return (
        True,
        "You are using default credentials. Please change your password "
        "immediately using POST /api/auth/password before performing "
        "sensitive operations.",
    )


async def create_login_tokens(
    user: User,
    session: AsyncSession,
    *,
    token_claims: dict[str, Any] | None = None,
) -> tuple[str, str]:
    """Create access and refresh tokens for a user.

    Args:
        user: The authenticated user
        session: Database session

    Returns:
        Tuple of (access_token, refresh_token)

    Raises:
        HTTPException: If user ID is not available
    """
    role = normalize_role(user.role)
    claims: dict[str, Any] = {
        "sub": user.email,
        "email": user.email,
        "name": user.name,
        "role": role,
        "roles": [role],
        "scopes": [],
        "provider": user.identity_provider or "local",
        "provider_subject": user.provider_subject,
        "tenant_id": user.tenant_id or "default",
        "session_assurance": "A1",
        "principal_risk": "R1",
    }
    if token_claims:
        claims.update(token_claims)

    access_token = create_access_token(
        data=claims,
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    # Create refresh token
    if user.id is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User ID not available",
        )
    refresh_token = await create_refresh_token(user.id, session)

    return access_token, refresh_token


async def complete_login(
    user: User,
    session: AsyncSession,
    *,
    options: LoginCompletionOptions | None = None,
    **legacy_kwargs: Any,
) -> LoginResponse:
    """Complete login process: update user, create session, log audit, return response.

    This handles the final steps of authentication (both password and passkey).
    Can optionally create a UserSession record for the login.

    Args:
        user: The authenticated user
        session: Database session
        user_agent: Optional user agent string (for device tracking)
        ip_address: Optional IP address of the client
        access_token: Access token (will be created if not provided)
        refresh_token: Refresh token (will be created if not provided)

    Returns:
        LoginResponse with tokens and user info
    """
    resolved_options = _parse_login_completion_options(options, legacy_kwargs)
    canonical_roles = _canonical_roles(user, resolved_options["roles"])
    canonical_scopes = _normalize_scopes(resolved_options["scopes"])
    _apply_login_identity(user, resolved_options)
    session.add(user)
    await db_commit(session)

    _, resolved_principal_risk = await ensure_user_identity_records(
        session,
        user=user,
        provider=resolved_options["provider"],
        provider_subject=resolved_options["provider_subject"],
        tenant_id=resolved_options["tenant_id"],
        roles=canonical_roles or [user.role],
    )
    await db_commit(session)
    principal_risk = resolved_options["principal_risk"] or resolved_principal_risk

    access_token = resolved_options["access_token"]
    refresh_token = resolved_options["refresh_token"]
    if access_token is None or refresh_token is None:
        token_claims = _build_login_token_claims(
            user,
            resolved_options,
            canonical_roles,
            canonical_scopes,
            principal_risk,
        )
        access_token, refresh_token = await create_login_tokens(
            user,
            session,
            token_claims=token_claims,
        )

    await _create_tracked_user_session(
        user,
        session,
        resolved_options,
        refresh_token,
    )

    await emit_audit_event(
        session,
        event_type="login",
        actor=user.email,
        result="success",
        details={
            "method": resolved_options["auth_method"],
            "role": user.role,
            "provider": resolved_options["provider"],
            "tenant_id": resolved_options["tenant_id"],
            "assurance": resolved_options["session_assurance"],
        },
    )
    await db_commit(session)

    must_change_password, security_warning = _build_security_warning(user)

    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",  # nosec B106
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserRead.model_validate(user),
        must_change_password=must_change_password,
        security_warning=security_warning,
        auth_provider=resolved_options["provider"],
        session_assurance=resolved_options["session_assurance"],
        principal_risk=principal_risk or "R1",
        tenant_id=resolved_options["tenant_id"],
        roles=canonical_roles or [user.role],
        scopes=canonical_scopes,
    )
