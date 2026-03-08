"""Passkey/WebAuthn authentication routes."""

import base64
import logging
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Annotated

import redis

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select, SQLModel
from slowapi import Limiter
from slowapi.util import get_remote_address

from ..audit import emit_audit_event
from ..models import (
    User,
    get_session,
)
from ..utils.db import execute as db_execute, commit as db_commit, refresh as db_refresh
from ..utils.webauthn_helper import (
    get_registration_options,
    verify_registration,
    get_authentication_options,
    verify_authentication,
    find_credential,
)
from .auth import (
    get_current_user,
    rate_limit_normal,
)
from .auth_helpers import complete_login, LoginResponse

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth/passkey", tags=["auth", "passkey"])
limiter = Limiter(key_func=get_remote_address)

# Challenge storage: Redis for multi-worker, in-memory fallback for single-worker
_CHALLENGE_TTL = 300  # 5 minutes
_redis_state: dict[str, redis.Redis | None] = {"client": None}
_webauthn_challenges: dict[str, tuple[bytes, float]] = {}
_INVALID_CREDENTIALS_MESSAGE = "Invalid credentials"


def _get_redis() -> redis.Redis | None:
    """Lazily connect to Redis if available."""
    redis_client = _redis_state["client"]
    if redis_client is not None:
        return redis_client
    redis_url = os.getenv("REDIS_URL", "")
    if redis_url and not redis_url.startswith("memory://"):
        try:
            redis_instance = redis.Redis.from_url(redis_url, decode_responses=False)
            redis_instance.ping()
            _redis_state["client"] = redis_instance
            logger.info("WebAuthn challenge store using Redis")
            return redis_instance
        except redis.ConnectionError as exc:
            logger.warning("Redis unavailable for WebAuthn challenges, using in-memory")
            logger.debug("Redis connection error: %s", exc)
    return None


def _purge_expired_challenges() -> None:
    """Remove expired in-memory challenges."""
    now = time.time()
    expired_keys = [
        key for key, (_, expires_at) in _webauthn_challenges.items() if expires_at <= now
    ]
    for key in expired_keys:
        _webauthn_challenges.pop(key, None)


def _store_challenge(challenge_id: str, challenge: bytes) -> None:
    """Store a challenge, using Redis if available."""
    r = _get_redis()
    if r:
        r.setex(f"webauthn:{challenge_id}", _CHALLENGE_TTL, challenge)
    else:
        _purge_expired_challenges()
        _webauthn_challenges[challenge_id] = (challenge, time.time() + _CHALLENGE_TTL)


def _normalize_cached_challenge(value: object) -> bytes | None:
    """Normalize Redis challenge payloads into raw bytes."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, str):
        return value.encode("utf-8")
    return None


def _pop_memory_challenge(challenge_id: str) -> bytes | None:
    """Pop an in-memory challenge if it exists and is not expired."""
    _purge_expired_challenges()
    challenge_entry = _webauthn_challenges.pop(challenge_id, None)
    if challenge_entry is None:
        return None
    challenge, expires_at = challenge_entry
    if expires_at <= time.time():
        return None
    return challenge


def _pop_challenge(challenge_id: str) -> bytes | None:
    """Retrieve and delete a challenge, using Redis if available."""
    r = _get_redis()
    if r:
        key = f"webauthn:{challenge_id}"
        value = r.get(key)
        if value is None:
            return None
        r.delete(key)
        return _normalize_cached_challenge(value)
    return _pop_memory_challenge(challenge_id)


class PasskeyRegisterRequest(SQLModel):
    """Request to register a new passkey."""

    name: str = "Passkey"


@router.post("/register-start")
def start_passkey_registration(
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    """Start passkey registration process.

    Generates registration options and a challenge for the client.
    User must be authenticated to register a passkey.
    """
    # Validate user ID is set (guaranteed after database commit)
    if current_user.id is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User not properly initialized",
        )

    user_id: int = current_user.id

    # Generate registration options
    options_data = get_registration_options(
        user_id=user_id,
        user_email=current_user.email,
        user_name=current_user.name or current_user.email,
        existing_credentials=current_user.webauthn_credentials or [],
    )

    # Store challenge temporarily
    challenge_id = secrets.token_urlsafe(32)
    _store_challenge(challenge_id, base64.b64decode(options_data["challenge"]))

    return {
        **options_data,
        "challenge_id": challenge_id,
    }


class PasskeyRegisterFinishRequest(SQLModel):
    """Request to finish passkey registration."""

    credential: dict
    challenge_id: str
    name: str = "Passkey"


@router.post("/register-finish")
async def finish_passkey_registration(
    request_data: PasskeyRegisterFinishRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    """Finish passkey registration.

    Verifies the credential and stores it for the user.
    """
    # Get stored challenge
    challenge = _pop_challenge(request_data.challenge_id)
    if not challenge:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired challenge",
        )

    # Validate user ID is set
    if current_user.id is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User not properly initialized",
        )

    user_id: int = current_user.id

    # Verify registration
    try:
        cred_data = verify_registration(
            credential=request_data.credential,
            expected_challenge=challenge,
            user_id=user_id,
        )
        cred_data["name"] = request_data.name

        # Add to user's credentials
        if current_user.webauthn_credentials is None:
            current_user.webauthn_credentials = []

        # Create new list to ensure SQLAlchemy detects change
        current_user.webauthn_credentials = [
            *current_user.webauthn_credentials,
            cred_data,
        ]

        session.add(current_user)
        await db_commit(session)

        # Audit log
        await emit_audit_event(
            session,
            event_type="passkey_registered",
            actor=current_user.email,
            result="success",
            details={"credential_id": cred_data["credential_id"][:16] + "..."},
        )
        await db_commit(session)

        return {
            "status": "registered",
            "credential_id": cred_data["credential_id"],
            "name": cred_data["name"],
        }
    except Exception as exc:  # pylint: disable=broad-exception-caught
        # Audit log
        await emit_audit_event(
            session,
            event_type="passkey_register",
            actor=current_user.email,
            result="failed",
            details={"error": str(exc)},
        )
        await db_commit(session)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Registration failed: {str(exc)}",
        ) from exc


class PasskeyLoginStartRequest(SQLModel):
    """Request to start passkey login."""

    email: str


@router.post("/login-start")
@limiter.limit(rate_limit_normal)
async def start_passkey_login(
    request: Request,
    login_request: PasskeyLoginStartRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    """Start passkey login process.

    Generates authentication options for a user's registered passkeys.
    """
    _ = request  # Used for rate limiting only

    result = await db_execute(session, select(User).where(User.email == login_request.email))
    user = result.scalar_one_or_none()
    if not user:
        # Don't reveal if user exists (timing-safe response)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_INVALID_CREDENTIALS_MESSAGE,
        )

    if not user.webauthn_credentials:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_INVALID_CREDENTIALS_MESSAGE,
        )

    # Generate authentication options
    options_data = get_authentication_options(
        existing_credentials=user.webauthn_credentials,
    )

    # Store challenge temporarily with user_id
    challenge_id = secrets.token_urlsafe(32)
    _store_challenge(f"{challenge_id}:{user.id}", base64.b64decode(options_data["challenge"]))

    return {
        "options": options_data["options"],
        "challenge_id": challenge_id,
    }


class PasskeyLoginFinishRequest(SQLModel):
    """Request to finish passkey login."""

    credential: dict
    challenge_id: str
    email: str


@router.post("/login-finish")
@limiter.limit(rate_limit_normal)
async def finish_passkey_login(
    request: Request,
    login_request: PasskeyLoginFinishRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> LoginResponse:
    """Finish passkey login.

    Verifies the authentication response and returns tokens.
    """
    _ = request  # Used for rate limiting only
    # Get user
    result = await db_execute(session, select(User).where(User.email == login_request.email))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # Get stored challenge
    challenge_key = f"{login_request.challenge_id}:{user.id}"
    challenge = _pop_challenge(challenge_key)
    if not challenge:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired challenge",
        )

    # Find the credential being used
    credential_id = login_request.credential.get("id") or login_request.credential.get("rawId")
    if not credential_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid credential format",
        )

    stored_credential = find_credential(user.webauthn_credentials or [], credential_id)
    if not stored_credential:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credential not found",
        )

    # Verify authentication
    success, new_sign_count = verify_authentication(
        credential=login_request.credential,
        expected_challenge=challenge,
        stored_credential=stored_credential,
    )

    if not success:
        # Audit log
        await emit_audit_event(
            session,
            event_type="passkey_login",
            actor=user.email,
            result="failed",
            details={"reason": "verification_failed"},
        )
        await db_commit(session)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
        )

    # Update sign count and last used
    stored_credential["sign_count"] = new_sign_count
    stored_credential["last_used"] = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()

    # Update user credentials
    existing_credentials = user.webauthn_credentials or []
    user.webauthn_credentials = [
        cred if cred["credential_id"] != credential_id else stored_credential
        for cred in existing_credentials
    ]

    # Complete login (create tokens, audit log)
    return await complete_login(
        user=user,
        session=session,
    )


@router.get("/list")
def list_passkeys(
    current_user: Annotated[User, Depends(get_current_user)],
) -> list[dict]:
    """List user's registered passkeys."""
    credentials = current_user.webauthn_credentials or []

    return [
        {
            "credential_id": cred["credential_id"],
            "name": cred["name"],
            "created_at": cred["created_at"],
            "last_used": cred["last_used"],
            "transports": cred.get("transports", []),
        }
        for cred in credentials
    ]


@router.delete("/{credential_id}")
async def delete_passkey(
    credential_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    """Delete a passkey."""
    if not current_user.webauthn_credentials:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Passkey not found",
        )

    # Find and remove credential
    original_count = len(current_user.webauthn_credentials)
    current_user.webauthn_credentials = [
        c for c in current_user.webauthn_credentials if c["credential_id"] != credential_id
    ]

    if len(current_user.webauthn_credentials) == original_count:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Passkey not found",
        )

    session.add(current_user)
    await db_commit(session)

    # Audit log
    await emit_audit_event(
        session,
        event_type="passkey_deleted",
        actor=current_user.email,
        result="success",
        details={"credential_id": credential_id[:16] + "..."},
    )
    await db_commit(session)

    return {"status": "deleted"}


class PasskeyRenameRequest(SQLModel):
    """Request to rename a passkey."""

    name: str


@router.patch("/{credential_id}")
async def rename_passkey(
    credential_id: str,
    rename_request: PasskeyRenameRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    """Rename a passkey."""
    if not current_user.webauthn_credentials:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Passkey not found",
        )

    # Find and rename credential
    credentials = current_user.webauthn_credentials or []
    found = False
    updated_credentials = []

    for cred in credentials:
        # Create a new dict to ensure change detection
        updated_cred = dict(cred)
        if cred["credential_id"] == credential_id:
            updated_cred["name"] = rename_request.name
            found = True
        updated_credentials.append(updated_cred)

    if not found:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Passkey not found",
        )

    # Reassign to trigger SQLAlchemy change detection
    current_user.webauthn_credentials = updated_credentials
    session.add(current_user)
    await db_commit(session)
    await db_refresh(session, current_user)

    # Audit log
    await emit_audit_event(
        session,
        event_type="passkey_renamed",
        actor=current_user.email,
        result="success",
        details={
            "credential_id": credential_id[:16] + "...",
            "new_name": rename_request.name,
        },
    )
    await db_commit(session)

    return {
        "status": "updated",
        "name": rename_request.name,
    }
