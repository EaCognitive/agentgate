"""Application lifespan management for FastAPI with async database lifecycle."""

import logging
from contextlib import asynccontextmanager
from importlib import import_module
from typing import cast

import bcrypt
from fastapi import FastAPI
from pydantic import SecretStr
from sqlalchemy.exc import OperationalError
from sqlmodel import select

from ea_agentgate.middleware.pii_vault import warmup as pii_vault_warmup
from .audit import set_event_bus
from .audit.bus import EventBus
from .audit.config import AuditPipelineMode
from .config import get_settings
from .models import (
    init_db as _legacy_init_db,
    close_db,
    get_session_context,
    User,
    UserPIIPermissions,
)
from .models.common_enums import PIIPermission
from .policy_governance.kernel.runtime_settings import (
    get_ai_write_governance_mode,
    get_scoped_reads_enabled,
    get_unknown_token_policy,
)
from .policy_governance.kernel.distributed_health_monitor import (
    start_distributed_health_monitor_from_environment,
    stop_distributed_health_monitor,
)
from .policy_governance.kernel.solver_engine import validate_runtime_z3_configuration
from .utils.db import commit as db_commit, execute as db_execute, refresh as db_refresh

logger = logging.getLogger(__name__)

# Backward-compatible alias for legacy tests that patch server.lifespan.init_db.
# Startup no longer invokes this schema bootstrap path.
init_db = _legacy_init_db


async def check_setup_required() -> bool:
    """Check if initial setup is required (no users exist).

    Returns:
        True if setup is required (no users in database).
    """
    try:
        async with get_session_context() as session:
            result = await db_execute(session, select(User).limit(1))
            existing = result.scalars().first()
            return existing is None
    except OperationalError as exc:
        error_text = str(exc).lower()
        missing_users_table = ("no such table" in error_text and "users" in error_text) or (
            "relation" in error_text and "users" in error_text and "does not exist" in error_text
        )
        if missing_users_table:
            logger.warning(
                "Users table not available during setup check; treating as setup required"
            )
            return True
        raise


class _SetupState:
    """Module-level state holder to avoid global keyword (REQ-SEC-03)."""

    _required: bool | None = None

    @classmethod
    def get(cls) -> bool | None:
        """Get current setup required state."""
        return cls._required

    @classmethod
    def set(cls, value: bool | None) -> None:
        """Set setup required state."""
        cls._required = value


def _extract_secret_value(value: object) -> str | None:
    """Return the plain-text value from a ``SecretStr`` when present."""
    if not isinstance(value, SecretStr):
        return None
    return value.get_secret_value()


def reset_setup_state() -> None:
    """Reset cached setup state so each check hits the database."""
    _SetupState.set(None)


async def is_setup_required() -> bool:
    """Return cached setup requirement status.

    This is set once during startup and updated after setup completes.
    """
    if _SetupState.get() is None:
        try:
            _SetupState.set(await check_setup_required())
        except OperationalError:
            logger.warning(
                "Setup requirement check failed due to database unavailability; "
                "defaulting to setup-required.",
                exc_info=True,
            )
            return True
    return _SetupState.get() is True


def mark_setup_complete() -> None:
    """Mark setup as complete (called after first admin is created)."""
    _SetupState.set(False)
    logger.info("Initial setup completed - system is now operational")


async def seed_default_admin() -> None:
    """Seed a default admin user when bootstrap credentials are configured.

    This path is opt-in via environment settings and is intended for controlled
    bootstrap environments. Browser-first setup remains the default path.
    """
    settings = get_settings()
    email = settings.default_admin_email
    password = settings.default_admin_password

    if not email or not password:
        return

    if not isinstance(email, str):
        return

    email_value = str(email)
    password_value = _extract_secret_value(password)

    if not password_value:
        return

    async with get_session_context() as session:
        existing_result = await db_execute(session, select(User).limit(1))
        existing_user = existing_result.scalars().first()
        if existing_user is not None:
            return

        hashed_password = bcrypt.hashpw(
            password_value.encode("utf-8"),
            bcrypt.gensalt(),
        ).decode("utf-8")

        admin = User(
            email=email_value,
            name="Default Admin",
            hashed_password=hashed_password,
            role="admin",
            must_change_password=True,
            is_default_credentials=True,
        )
        session.add(admin)
        await db_commit(session)
        await db_refresh(session, admin)

        if admin.id is None:
            logger.error("Default admin seed failed: user ID not assigned after refresh")
            return

        for permission in PIIPermission:
            session.add(
                UserPIIPermissions(
                    user_id=admin.id,
                    permission=permission.value,
                    granted_by=admin.id,
                    reason="Default admin bootstrap seed",
                )
            )
        await db_commit(session)

    logger.warning("Default admin account seeded from environment; rotate credentials immediately.")


async def _run_startup_checks() -> None:
    """Execute setup gate evaluation and governance settings check.

    Seeds the default admin if configured, evaluates whether initial
    setup is required, and logs runtime governance settings from the
    database.  All database-unavailable scenarios are handled
    gracefully so that startup proceeds.
    """
    try:
        await seed_default_admin()
    except OperationalError:
        logger.warning(
            "Default admin seed skipped because database is unavailable.",
            exc_info=True,
        )

    try:
        setup_needed = await check_setup_required()
    except OperationalError:
        logger.warning(
            "Startup setup check failed because database is "
            "unavailable; deferring to readiness probe.",
            exc_info=True,
        )
        setup_needed = True
    _SetupState.set(setup_needed)
    if setup_needed:
        logger.warning(
            "SETUP REQUIRED: No users exist. "
            "Complete initial setup via browser at "
            "/api/setup/status"
        )
    else:
        logger.info("System initialized with existing users")

    try:
        async with get_session_context() as runtime_session:
            governance_mode = await get_ai_write_governance_mode(
                runtime_session,
            )
            unknown_token_policy = await get_unknown_token_policy(
                runtime_session,
            )
            scoped_reads_enabled = await get_scoped_reads_enabled(
                runtime_session,
            )
            z3_runtime_status = validate_runtime_z3_configuration(
                require_solver_health=True,
            )
            logger.info(
                (
                    "Runtime governance mode=%s scoped_reads=%s "
                    "pii_unknown_token_policy=%s "
                    "z3_mode=%s z3_check=%s"
                ),
                governance_mode,
                scoped_reads_enabled,
                unknown_token_policy,
                z3_runtime_status["configured_mode"],
                z3_runtime_status["z3_check_result"],
            )
    except OperationalError:
        logger.warning(
            "Runtime governance settings check skipped because database is unavailable.",
            exc_info=True,
        )
    except RuntimeError:
        logger.exception(
            "Runtime solver configuration check failed during startup.",
        )
        raise
    except (AttributeError, KeyError, TypeError, ValueError):
        logger.exception(
            "Unexpected error while collecting runtime governance settings at startup."
        )

    try:
        await pii_vault_warmup()
    except RuntimeError:
        logger.warning(
            "PII vault warmup skipped due to error",
            exc_info=True,
        )


async def _start_audit_pipeline(settings):
    """Conditionally start the async Redis audit pipeline.

    When the audit pipeline is configured for Redis streams and a valid
    Redis URL is provided, this helper initialises the event bus and
    returns a running ``StreamConsumer``.  Otherwise returns ``None``.

    Args:
        settings: Application settings object.

    Returns:
        A running ``StreamConsumer`` instance, or ``None``.
    """
    pipeline_mode = str(
        settings.model_dump().get("audit_pipeline", ""),
    ).lower()

    if (
        pipeline_mode == AuditPipelineMode.REDIS_STREAM.value
        and settings.redis_url
        and settings.redis_url != "memory://"
    ):
        try:
            async_redis = getattr(import_module("redis.asyncio"), "Redis")
            redis_stream_event_bus = getattr(
                import_module("server.audit.bus"),
                "RedisStreamEventBus",
            )
            stream_consumer = getattr(
                import_module("server.audit.consumer"),
                "StreamConsumer",
            )

            redis_client = async_redis.from_url(
                settings.redis_url,
                decode_responses=True,
            )
            set_event_bus(cast(EventBus, redis_stream_event_bus(redis_client)))
            consumer = stream_consumer(redis_client)
            await consumer.start()
            logger.info("Audit pipeline: redis_stream (async)")
            return consumer
        except (
            AttributeError,
            ConnectionError,
            ImportError,
            OSError,
            RuntimeError,
            ValueError,
        ):
            logger.exception("Failed to start Redis audit pipeline; falling back to sync")
            return None

    logger.info("Audit pipeline: sync (default)")
    return None


@asynccontextmanager
async def lifespan(fastapi_app: FastAPI):
    """Initialize database on startup, cleanup on shutdown."""
    _ = fastapi_app  # Required by FastAPI signature
    reset_setup_state()

    await _run_startup_checks()

    settings = get_settings()
    consumer = await _start_audit_pipeline(settings)

    distributed_health_monitor = None
    try:
        distributed_health_monitor = await start_distributed_health_monitor_from_environment()
    except RuntimeError:
        logger.exception("Failed to start distributed health monitor due to runtime configuration")
    except (AttributeError, ConnectionError, OSError, TypeError, ValueError):
        logger.exception("Failed to start distributed health monitor")

    yield

    # Cleanup on shutdown
    if distributed_health_monitor is not None:
        await stop_distributed_health_monitor()
    if consumer is not None:
        await consumer.stop()
    await close_db()
