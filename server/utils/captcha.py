"""CAPTCHA verification utilities for login security.

This module provides hCaptcha verification and failed login tracking
to protect against brute force attacks.
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from sqlmodel import select

from server.models.schemas import User
from .db import execute as db_execute, commit as db_commit, refresh as db_refresh


class _HCaptchaClientHolder:
    """Holds a shared httpx client to avoid per-request connection overhead."""

    client: httpx.AsyncClient | None = None

    @classmethod
    def get(cls) -> httpx.AsyncClient:
        """Return the shared client, creating it if needed."""
        if cls.client is None or cls.client.is_closed:
            cls.client = httpx.AsyncClient(timeout=10.0)
        return cls.client

    @classmethod
    async def close(cls) -> None:
        """Close and clear the shared client when the runtime shuts down."""
        if cls.client is not None and not cls.client.is_closed:
            await cls.client.aclose()
        cls.client = None


def _first_user_from_result(result: Any) -> User | None:
    """Extract first User row from SQLModel/SQLAlchemy execute results."""
    if hasattr(result, "scalars"):
        candidate = result.scalars().first()
        return candidate if isinstance(candidate, User) else None

    first_row = result.first()
    if first_row is None:
        return None
    if isinstance(first_row, User):
        return first_row
    try:
        candidate = first_row[0]
    except (TypeError, KeyError, IndexError):
        return None
    return candidate if isinstance(candidate, User) else None


async def verify_hcaptcha(token: str, remote_ip: str | None = None) -> bool:
    """Verify hCaptcha token with hCaptcha service.

    Args:
        token: hCaptcha response token from client
        remote_ip: Optional IP address of client for additional validation

    Returns:
        True if verification successful, False otherwise

    Raises:
        ValueError: If HCAPTCHA_SECRET not configured in production
    """
    secret = os.getenv("HCAPTCHA_SECRET")
    if not secret:
        # In development or testing without CAPTCHA configured, allow through
        env = os.getenv("AGENTGATE_ENV", "development")
        if env in ("development", "test"):
            return True
        raise ValueError("HCAPTCHA_SECRET not configured")

    try:
        client = _HCaptchaClientHolder.get()
        response = await client.post(
            "https://hcaptcha.com/siteverify",
            data={
                "secret": secret,
                "response": token,
                "remoteip": remote_ip,
            },
        )
        result = response.json()
        return bool(result.get("success", False))  # type: ignore[no-any-return]
    except (httpx.RequestError, ValueError):
        # On error, fail closed (require CAPTCHA)
        return False
    except Exception:  # pylint: disable=broad-exception-caught
        # Catch unexpected errors and fail closed
        return False


async def requires_captcha(user_email: str, session) -> bool:
    """Check if user requires CAPTCHA based on failed login attempts.

    Args:
        user_email: Email address of user
        session: Database session (async)

    Returns:
        True if CAPTCHA required (3+ failed attempts), False otherwise
    """
    result = await db_execute(session, select(User).where(User.email == user_email))
    user = _first_user_from_result(result)
    if not user:
        # Don't reveal if user exists
        return False

    # Reset counter after 1 hour of inactivity
    if user.last_failed_login:
        last_failed = user.last_failed_login.replace(tzinfo=None)
        time_since_last_failure = datetime.now(timezone.utc).replace(tzinfo=None) - last_failed
        if time_since_last_failure > timedelta(hours=1):
            user.failed_login_attempts = 0
            user.last_failed_login = None
            session.add(user)
            await db_commit(session)
            return False

    # Require CAPTCHA after 3 failed attempts
    return bool(user.failed_login_attempts >= 3)  # type: ignore[no-any-return]


async def increment_failed_login(user_email: str, session) -> None:
    """Increment failed login counter for user.

    Args:
        user_email: Email address of user
        session: Database session (async)
    """
    result = await db_execute(session, select(User).where(User.email == user_email))
    user = _first_user_from_result(result)
    if user:
        user.failed_login_attempts += 1
        user.last_failed_login = datetime.now(timezone.utc).replace(tzinfo=None)
        session.add(user)
        await db_commit(session)
        await db_refresh(session, user)


async def reset_failed_login(user_email: str, session) -> None:
    """Reset failed login counter after successful login.

    Args:
        user_email: Email address of user
        session: Database session (async)
    """
    result = await db_execute(session, select(User).where(User.email == user_email))
    user = _first_user_from_result(result)
    if user:
        user.failed_login_attempts = 0
        user.last_failed_login = None
        session.add(user)
        await db_commit(session)
        await db_refresh(session, user)
