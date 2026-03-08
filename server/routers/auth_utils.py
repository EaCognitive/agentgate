"""Authentication utility functions."""

import asyncio
import os
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import RefreshToken, User
from ..utils.secret_loader import get_runtime_secret
from ..utils.mfa import verify_totp_code
from ..utils.db import commit as db_commit


def _get_secret_key() -> str:
    """Get and validate SECRET_KEY from keyring or environment."""
    key = get_runtime_secret("SECRET_KEY")
    if not key:
        env = os.getenv("AGENTGATE_ENV", "development")
        fallback_allowed = os.getenv("ALLOW_SECRET_KEY_FALLBACK", "").lower() == "true"
        if env in ("development", "test") or fallback_allowed:
            return "dev-secret-key-for-local-development-only-32chars"
        raise RuntimeError(
            "SECRET_KEY environment variable not set (keyring/env lookup failed). "
            "Generate with: python -c 'import secrets; print(secrets.token_urlsafe(32))'"
        )
    if len(key) < 32:
        raise ValueError("SECRET_KEY must be at least 32 characters for production security")
    return key


ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7


class _SecretKeyHolder:
    """Lazy cache for SECRET_KEY.

    Defers env-var lookup so that production secrets loaded at
    runtime (e.g. via Google Secret Manager) are available before
    the value is first read.
    """

    _value: str | None = None

    @classmethod
    def get(cls) -> str:
        """Return the secret key, computing on first access."""
        if cls._value is None:
            cls._value = _get_secret_key()
        return cls._value

    @classmethod
    def reset(cls) -> None:
        """Clear cached value (useful for tests)."""
        cls._value = None


def get_secret_key() -> str:
    """Public accessor for the lazily-loaded SECRET_KEY."""
    return _SecretKeyHolder.get()


def _verify_password_sync(plain_password: str, hashed_password: str) -> bool:
    """Synchronous password verification."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except ValueError:
        return False


def _get_password_hash_sync(password: str) -> str:
    """Synchronous password hashing."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


async def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Async password verification."""
    return await asyncio.to_thread(_verify_password_sync, plain_password, hashed_password)


async def get_password_hash(password: str) -> str:
    """Async password hashing."""
    return await asyncio.to_thread(_get_password_hash_sync, password)


def parse_user_agent(user_agent: str | None) -> tuple[str, str]:
    """Parse device and browser from User-Agent."""
    if not user_agent:
        return ("Unknown", "Unknown")
    ua = user_agent.lower()
    device = (
        "Mobile" if any(k in ua for k in ["mobile", "android", "iphone", "ipad"]) else "Desktop"
    )
    if "edg" in ua:
        browser = "Edge"
    elif "chrome" in ua and "safari" in ua:
        browser = "Chrome"
    elif "firefox" in ua:
        browser = "Firefox"
    elif "safari" in ua:
        browser = "Safari"
    else:
        browser = "Unknown"
    return (device, browser)


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Create a new JWT access token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc).replace(tzinfo=None) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, get_secret_key(), algorithm=ALGORITHM)


async def create_refresh_token(user_id: int, session: AsyncSession) -> str:
    """Create and store a refresh token."""
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(
        days=REFRESH_TOKEN_EXPIRE_DAYS
    )
    refresh_token = RefreshToken(
        token=token,
        user_id=user_id,
        expires_at=expires_at,
    )
    session.add(refresh_token)
    await db_commit(session)
    return token


async def _verify_mfa(user: User, code: str, session: AsyncSession) -> bool:
    """Verify TOTP or backup code."""
    if user.totp_secret and verify_totp_code(user.totp_secret, code):
        return True
    if user.backup_codes:
        matched_hash = None
        normalized_code = code.strip().upper()
        code_bytes = normalized_code.encode("utf-8")
        for hashed in user.backup_codes:
            try:
                if bcrypt.checkpw(code_bytes, hashed.encode("utf-8")):
                    matched_hash = hashed
                    break
            except (ValueError, TypeError):
                continue
        if matched_hash:
            user.backup_codes = [c for c in user.backup_codes if c != matched_hash]
            session.add(user)
            await db_commit(session)
            return True
    return False
