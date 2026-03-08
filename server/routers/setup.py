"""First-time setup endpoints for AgentGate.

Provides secure initial configuration:
1. Check if setup is required (no users exist)
2. Create initial admin account with strong credentials
3. Generate API key for MCP/automation
4. Return credentials for secure storage
"""

from __future__ import annotations

import logging
import os
import re
from urllib.parse import urlsplit
from typing import Annotated

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select, SQLModel, Field

from ..audit import emit_audit_event
from ..cors_config import get_allowed_origins
from ..lifespan import is_setup_required, mark_setup_complete, reset_setup_state
from ..models import User, get_session
from ..utils.db import (
    commit as db_commit,
    execute as db_execute,
    flush as db_flush,
    refresh as db_refresh,
    rollback as db_rollback,
)
from .api_keys import generate_api_key, APIKey
from ..policy_governance.kernel.credential_check import is_default_email

router = APIRouter(prefix="/setup", tags=["setup"])
logger = logging.getLogger(__name__)


async def _find_missing_setup_tables(
    session: AsyncSession,
    required_tables: set[str],
) -> list[str]:
    """Return missing setup prerequisite tables from active database schema."""
    if not required_tables:
        return []

    try:
        connection = await session.connection()
        table_names = await connection.run_sync(
            lambda sync_connection: set(inspect(sync_connection).get_table_names())
        )
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as exc:
        logger.warning("Unable to inspect setup prerequisite tables: %s", exc)
        return []

    return sorted(required_tables.difference(table_names))


def _is_allowed_browser_origin(origin: str) -> bool:
    """Validate that request origin is an allowed browser origin."""
    allowed_origins = get_allowed_origins()
    normalized_origin = origin.rstrip("/")
    normalized_allowed = {allowed.rstrip("/") for allowed in allowed_origins if allowed}

    # Always trust explicitly configured dashboard origins for first-time setup.
    dashboard_env_keys = (
        "AGENTGATE_DASHBOARD_URL",
        "NEXT_PUBLIC_DASHBOARD_URL",
        "DASHBOARD_URL",
    )
    for env_key in dashboard_env_keys:
        env_value = (os.getenv(env_key) or "").strip().rstrip("/")
        if env_value:
            normalized_allowed.add(env_value)

    # Development fallback for local browser onboarding.
    if not normalized_allowed:
        normalized_allowed.update(
            {
                "http://localhost:3000",
                "http://127.0.0.1:3000",
            }
        )

    if normalized_origin in normalized_allowed:
        return True

    # Accept loopback host equivalence between localhost and 127.0.0.1
    # when scheme and port match a configured origin.
    parsed = urlsplit(normalized_origin)
    for allowed_origin in normalized_allowed:
        allowed = urlsplit(allowed_origin)
        same_scheme = parsed.scheme == allowed.scheme
        same_port = parsed.port == allowed.port
        host_pair = {parsed.hostname, allowed.hostname}
        if same_scheme and same_port and host_pair == {"localhost", "127.0.0.1"}:
            return True

    return False


def _enforce_browser_setup_request(request: Request) -> None:
    """Require setup completion to be called from the dashboard browser flow."""
    origin = (request.headers.get("origin") or "").strip()
    referer = (request.headers.get("referer") or "").strip()

    if origin and _is_allowed_browser_origin(origin):
        return

    if referer:
        referer_base = referer.split("/", 3)[:3]
        if len(referer_base) == 3:
            referer_origin = "/".join(referer_base)
            if _is_allowed_browser_origin(referer_origin):
                return

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=(
            "Initial setup must be completed from the dashboard browser interface. "
            "Open the dashboard and complete setup there."
        ),
    )


class SetupStatus(SQLModel):
    """Current setup status."""

    setup_required: bool
    user_count: int
    message: str


class SetupRequest(SQLModel):
    """Request to complete initial setup."""

    email: str = Field(min_length=5, max_length=320)
    password: str = Field(min_length=12, max_length=128)
    name: str = Field(default="Admin", min_length=1, max_length=120)
    generate_api_key: bool = Field(default=True)
    api_key_name: str = Field(default="mcp-default", max_length=128)


class SetupResponse(SQLModel):
    """Response after completing setup."""

    success: bool
    user_id: int
    email: str
    role: str
    api_key: str | None = None
    api_key_prefix: str | None = None
    credentials_file_hint: str
    next_steps: list[str]


def validate_password_strength(password: str) -> tuple[bool, str | None]:
    """Validate password meets security requirements.

    Requirements:
    - Minimum 12 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    - Not a known weak password
    """
    checks = [
        (len(password) >= 12, "Password must be at least 12 characters"),
        (re.search(r"[A-Z]", password), "Password must contain at least one uppercase letter"),
        (re.search(r"[a-z]", password), "Password must contain at least one lowercase letter"),
        (re.search(r"\d", password), "Password must contain at least one digit"),
        (
            re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password),
            "Password must contain at least one special character",
        ),
    ]
    for passed, message in checks:
        if not passed:
            return False, message

    # Check for common weak passwords
    weak_patterns = [
        "password",
        "123456",
        "qwerty",
        "admin",
        "letmein",
        "welcome",
        "monkey",
        "dragon",
        "master",
        "login",
    ]
    lower_pass = password.lower()
    for weak in weak_patterns:
        if weak in lower_pass:
            return False, f"Password contains weak pattern: {weak}"

    return True, None


def validate_email(email: str) -> tuple[bool, str | None]:
    """Validate email format and block known defaults."""
    # Basic format check
    if not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email):
        return False, "Invalid email format"

    # Block default emails in production
    env = os.getenv("AGENTGATE_ENV", "development")
    if env == "production" and is_default_email(email):
        return False, "Default email addresses cannot be used in production"

    return True, None


@router.get("/status", response_model=SetupStatus)
async def get_setup_status(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> SetupStatus:
    """Check if initial setup is required.

    Returns setup_required=True if no users exist in the system.
    """
    result = await db_execute(session, select(User).limit(1))
    existing = result.scalars().first()

    if existing:
        return SetupStatus(
            setup_required=False,
            user_count=1,  # At least one exists
            message="Setup already completed. Use /login to authenticate.",
        )

    return SetupStatus(
        setup_required=True,
        user_count=0,
        message="No users found. Complete setup to create admin account.",
    )


async def _validate_setup_preconditions(
    request: Request,
    setup_data: SetupRequest,
    session: AsyncSession,
) -> None:
    """Validate all preconditions before creating the admin account.

    Raises HTTPException if any validation fails.
    """
    _enforce_browser_setup_request(request)

    if not await is_setup_required():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Setup already completed. Initial setup endpoint is no longer available.",
        )

    result = await db_execute(session, select(User).limit(1))
    existing = result.scalars().first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Setup already completed. Cannot create another admin via setup.",
        )

    email_valid, email_error = validate_email(setup_data.email)
    if not email_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=email_error,
        )

    pass_valid, pass_error = validate_password_strength(setup_data.password)
    if not pass_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=pass_error,
        )

    required_tables = {"audit_log", "users"}
    if setup_data.generate_api_key:
        required_tables.add("api_keys")
    missing_tables = await _find_missing_setup_tables(session, required_tables)
    if missing_tables:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "setup_prerequisite_tables_missing",
                "missing_tables": missing_tables,
                "message": (
                    "Setup prerequisites are missing from the database schema. "
                    "Run migrations before completing setup."
                ),
            },
        )


async def _create_admin_user(
    session: AsyncSession,
    setup_data: SetupRequest,
) -> tuple[User, str | None, str | None]:
    """Create the admin user and optional API key within a transaction.

    Returns:
        Tuple of (admin_user, api_key_value, api_key_prefix).
    """
    hashed_password = bcrypt.hashpw(
        setup_data.password.encode("utf-8"),
        bcrypt.gensalt(),
    ).decode("utf-8")

    api_key_value = None
    api_key_prefix = None

    admin = User(
        email=setup_data.email,
        name=setup_data.name,
        hashed_password=hashed_password,
        role="admin",
        must_change_password=False,
        is_default_credentials=False,
    )

    try:
        session.add(admin)
        await db_flush(session)
        if admin.id is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create admin account.",
            )

        if setup_data.generate_api_key:
            full_key, key_hash, key_prefix = generate_api_key()
            api_key_record = APIKey(
                name=setup_data.api_key_name,
                key_hash=key_hash,
                key_prefix=key_prefix,
                user_id=admin.id,
                scopes="*",
            )
            session.add(api_key_record)
            api_key_value = full_key
            api_key_prefix = key_prefix

        await emit_audit_event(
            session,
            event_type="initial_setup_completed",
            actor=setup_data.email,
            result="success",
            details={
                "admin_email": setup_data.email,
                "api_key_generated": setup_data.generate_api_key,
            },
        )
        await db_commit(session)
    except HTTPException:
        await db_rollback(session)
        raise
    except Exception as exc:
        await db_rollback(session)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=("Setup failed due to database persistence error. Verify migrations and retry."),
        ) from exc

    await db_refresh(session, admin)
    return admin, api_key_value, api_key_prefix


@router.post("/complete", response_model=SetupResponse)
async def complete_setup(
    request: Request,
    setup_data: SetupRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> SetupResponse:
    """Complete initial setup by creating the first admin account.

    This endpoint:
    1. Validates that no users exist (setup not already done)
    2. Validates password strength requirements
    3. Creates admin user with secure credentials
    4. Optionally generates an API key for MCP authentication
    5. Returns credentials for secure storage

    IMPORTANT: This endpoint can only be called once (when no users exist).
    """
    await _validate_setup_preconditions(request, setup_data, session)

    admin, api_key_value, api_key_prefix = await _create_admin_user(session, setup_data)

    mark_setup_complete()

    if admin.id is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Admin user creation did not return a persistent identifier",
        )

    return SetupResponse(
        success=True,
        user_id=admin.id,
        email=admin.email,
        role=admin.role,
        api_key=api_key_value,
        api_key_prefix=api_key_prefix,
        credentials_file_hint="~/.ea-agentgate/credentials.json",
        next_steps=[
            "Store the API key securely - it will not be shown again!",
            "Set MCP_AUTH_TOKEN environment variable with the API key",
            "Or use mcp_auth_browser() for interactive login",
            "Configure MCP_API_URL to point to your server",
        ],
    )


@router.post("/reset")
async def request_setup_reset(
    _session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    """Request information about resetting setup (admin recovery).

    This does NOT actually reset - provides guidance only.
    Actual reset requires direct database access for security.
    """
    reset_setup_state()
    return {
        "message": "Setup reset requires direct database access for security.",
        "instructions": [
            "1. Stop the AgentGate server",
            "2. Connect to the database directly",
            "3. Delete all users: DELETE FROM users;",
            "4. Delete all API keys: DELETE FROM api_keys;",
            "5. Delete active sessions: DELETE FROM user_sessions;",
            "6. Delete refresh tokens: DELETE FROM refresh_tokens;",
            "7. Restart the server",
            "8. Call POST /api/setup/complete with new credentials",
        ],
        "warning": "This will delete ALL user data. Ensure you have backups.",
    }
