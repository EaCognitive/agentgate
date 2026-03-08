"""Database configuration and async session management."""

from __future__ import annotations

import inspect
import os
import sqlite3
import time
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any
from collections.abc import AsyncGenerator

from sqlalchemy import event, text
from sqlalchemy.engine.url import make_url
from sqlalchemy.exc import DisconnectionError
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool
from sqlmodel import SQLModel, Session, create_engine as create_sync_engine

from server.runtime.profile import RuntimeProfile, resolve_runtime_profile
from server.security.azure.postgres_token_provider import (
    AzurePostgresTokenProvider,
    create_azure_postgres_token_provider,
)

SCHEMA_INIT_LOCK_ID = 841_270_091
TOKEN_EXPIRY_WINDOW_SECONDS = 300
POOL_RECYCLE_MIN_SECONDS = 60
POOL_RECYCLE_MAX_SECONDS = 3_300
DEFAULT_TOKEN_POOL_RECYCLE_SECONDS = 3_000
DEFAULT_PASSWORD_POOL_RECYCLE_SECONDS = 3_600


class ProductionDatabaseError(Exception):
    """Raised when production or strict profiles use unsupported DB configuration."""


class DatabaseConfigurationError(Exception):
    """Raised when DATABASE_* environment values are invalid."""


def _env_flag(name: str) -> bool:
    """Read a boolean environment variable."""
    value = os.getenv(name, "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    """Read an integer environment variable with strict validation."""
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        return int(raw_value)
    except ValueError as exc:
        raise DatabaseConfigurationError(
            f"Environment variable {name} must be an integer."
        ) from exc


def _validate_production_database(db_url: str, environment: str) -> None:
    """Validate database configuration for production environments."""
    if environment != "production":
        return

    if "sqlite" in db_url.lower() or ":memory:" in db_url.lower():
        raise ProductionDatabaseError(
            "SQLite/memory database is not supported in production. "
            "Set DATABASE_URL to a PostgreSQL connection string."
        )


def _configure_sqlite_adapters() -> None:
    """Register explicit adapters to avoid sqlite3 datetime deprecation warnings."""
    sqlite3.register_adapter(datetime, lambda value: value.isoformat(" "))


def _default_sqlite_database_url() -> str:
    """Build a default SQLite URL for local compatibility profile."""
    state_dir_value = os.getenv("AGENTGATE_STATE_DIR")
    if not state_dir_value:
        return "sqlite+aiosqlite:///./agentgate.db"

    state_dir = Path(state_dir_value).expanduser()
    state_dir.mkdir(parents=True, exist_ok=True)
    database_path = state_dir / "agentgate.db"
    return f"sqlite+aiosqlite:///{database_path}"


def _normalize_database_url(db_url: str) -> str:
    """Normalize provider URLs into SQLAlchemy async URLs."""
    normalized = db_url
    if normalized.startswith("postgres://"):
        normalized = normalized.replace("postgres://", "postgresql+asyncpg://", 1)
    elif normalized.startswith("postgresql://"):
        normalized = normalized.replace("postgresql://", "postgresql+asyncpg://", 1)

    if normalized.startswith("sqlite://") and not normalized.startswith("sqlite+aiosqlite://"):
        normalized = normalized.replace("sqlite://", "sqlite+aiosqlite://", 1)

    parsed = make_url(normalized)
    if parsed.drivername == "postgresql+asyncpg":
        query = dict(parsed.query)
        sslmode = query.pop("sslmode", None)
        if sslmode is not None and "ssl" not in query:
            query["ssl"] = str(sslmode)
        parsed = parsed.set(query=query)
        normalized = parsed.render_as_string(hide_password=False)
    return normalized


def _to_sync_database_url(async_database_url: str) -> str:
    """Convert async SQLAlchemy URL to sync URL with driver/query compatibility."""
    sync_url = async_database_url.replace("+asyncpg", "").replace("+aiosqlite", "")
    parsed = make_url(sync_url)
    if parsed.drivername != "postgresql":
        return sync_url

    query = dict(parsed.query)
    ssl = query.pop("ssl", None)
    if ssl is not None and "sslmode" not in query:
        query["sslmode"] = str(ssl)

    normalized = parsed.set(
        drivername="postgresql+psycopg2",
        query=query,
    )
    return normalized.render_as_string(hide_password=False)


def _url_has_password(db_url: str) -> bool:
    """Check whether the SQLAlchemy URL contains static password material."""
    parsed = make_url(db_url)
    return parsed.password is not None


def _strip_password_from_database_url(db_url: str) -> str:
    """Remove password material from a database URL string."""
    parsed = make_url(db_url)
    return parsed.set(password=None).render_as_string(hide_password=False)


def _resolve_database_auth_mode(
    *,
    requested_mode: str,
    runtime_profile: RuntimeProfile,
    is_postgres: bool,
) -> str:
    """Resolve effective DB auth mode from runtime profile and env override."""
    if not is_postgres:
        return "password"

    normalized_mode = requested_mode.strip().lower()
    if not normalized_mode:
        normalized_mode = "auto"

    valid_modes = {"auto", "password", "entra_token"}
    if normalized_mode not in valid_modes:
        allowed = ", ".join(sorted(valid_modes))
        raise DatabaseConfigurationError(f"AGENTGATE_DB_AUTH_MODE must be one of: {allowed}.")

    if normalized_mode == "auto":
        if runtime_profile in {RuntimeProfile.DEV_CLOUD, RuntimeProfile.CLOUD_STRICT}:
            resolved = "entra_token"
        else:
            resolved = "password"
    else:
        resolved = normalized_mode

    if runtime_profile == RuntimeProfile.CLOUD_STRICT and resolved != "entra_token":
        raise ProductionDatabaseError(
            "cloud_strict profile requires Entra token authentication for PostgreSQL."
        )
    return resolved


def _requested_database_auth_mode() -> str:
    """Resolve DB auth mode from preferred and compatibility environment keys."""
    preferred = os.getenv("DATABASE_AUTH_MODE")
    if preferred is not None:
        return preferred
    return os.getenv("AGENTGATE_DB_AUTH_MODE", "auto")


def _compute_pool_recycle_seconds(value: int, token_auth_enabled: bool) -> int:
    """Clamp pool recycle settings to avoid stale token-bound pooled connections."""
    if value < POOL_RECYCLE_MIN_SECONDS:
        return POOL_RECYCLE_MIN_SECONDS
    if not token_auth_enabled:
        return value
    if value > POOL_RECYCLE_MAX_SECONDS:
        return POOL_RECYCLE_MAX_SECONDS
    return value


def _inject_entra_token_connect_params(
    *,
    cparams: dict[str, Any],
    connection_record: Any,
    token_provider: AzurePostgresTokenProvider,
) -> None:
    """Inject a fresh Entra token into connect params for physical DB connects."""
    token = token_provider.get_access_token()
    cparams["password"] = token.token
    info = getattr(connection_record, "info", None)
    if isinstance(info, dict):
        info["azure_access_token_expires_on"] = token.expires_on


def _invalidate_near_expiry_connection(
    *,
    connection_record: Any,
    min_ttl_seconds: int,
    now_epoch: int | None = None,
) -> None:
    """Fail pool checkout when token expiry is within safety window."""
    info = getattr(connection_record, "info", None)
    if not isinstance(info, dict):
        return

    expires_on = info.get("azure_access_token_expires_on")
    if not isinstance(expires_on, int):
        return

    current_epoch = int(time.time()) if now_epoch is None else now_epoch
    if current_epoch < (expires_on - min_ttl_seconds):
        return

    invalidate = getattr(connection_record, "invalidate", None)
    if callable(invalidate):
        invalidate()
    raise DisconnectionError("Discarding near-expiry pooled connection to refresh Entra DB token.")


def _register_entra_token_pool_hooks(
    *,
    target_engine: AsyncEngine,
    token_provider: AzurePostgresTokenProvider,
    min_ttl_seconds: int,
) -> None:
    """Register SQLAlchemy event hooks for dynamic token lifecycle control."""

    @event.listens_for(target_engine.sync_engine, "do_connect")
    def _do_connect(
        dialect: Any,
        conn_rec: Any,
        cargs: Any,
        cparams: dict[str, Any],
    ) -> None:
        _ = dialect, cargs
        _inject_entra_token_connect_params(
            cparams=cparams,
            connection_record=conn_rec,
            token_provider=token_provider,
        )

    @event.listens_for(target_engine.sync_engine.pool, "checkout")
    def _checkout(dbapi_conn: Any, conn_rec: Any, conn_proxy: Any) -> None:
        _ = dbapi_conn, conn_proxy
        _invalidate_near_expiry_connection(
            connection_record=conn_rec,
            min_ttl_seconds=min_ttl_seconds,
        )


def _register_sync_entra_token_pool_hooks(
    *,
    target_engine: Any,
    token_provider: AzurePostgresTokenProvider,
    min_ttl_seconds: int,
) -> None:
    """Register token hooks for synchronous engines used by CLI workflows."""

    @event.listens_for(target_engine, "do_connect")
    def _do_connect(
        dialect: Any,
        conn_rec: Any,
        cargs: Any,
        cparams: dict[str, Any],
    ) -> None:
        _ = dialect, cargs
        _inject_entra_token_connect_params(
            cparams=cparams,
            connection_record=conn_rec,
            token_provider=token_provider,
        )

    @event.listens_for(target_engine.pool, "checkout")
    def _checkout(dbapi_conn: Any, conn_rec: Any, conn_proxy: Any) -> None:
        _ = dbapi_conn, conn_proxy
        _invalidate_near_expiry_connection(
            connection_record=conn_rec,
            min_ttl_seconds=min_ttl_seconds,
        )


_configure_sqlite_adapters()

RAW_DATABASE_URL = os.getenv("DATABASE_URL", _default_sqlite_database_url())
_ENVIRONMENT = os.getenv("AGENTGATE_ENV", "development")
RUNTIME_PROFILE = resolve_runtime_profile(environment=_ENVIRONMENT)
DATABASE_URL = _normalize_database_url(RAW_DATABASE_URL)

_validate_production_database(DATABASE_URL, _ENVIRONMENT)

_is_sqlite = "sqlite" in DATABASE_URL.lower()
_is_postgres = DATABASE_URL.startswith("postgresql+asyncpg://")
_use_null_pool = _env_flag("DATABASE_POOL_DISABLED")

if RUNTIME_PROFILE == RuntimeProfile.CLOUD_STRICT and _is_sqlite:
    raise ProductionDatabaseError(
        "cloud_strict profile requires PostgreSQL and cannot run on SQLite."
    )

REQUESTED_DATABASE_AUTH_MODE = _requested_database_auth_mode()
DATABASE_AUTH_MODE = _resolve_database_auth_mode(
    requested_mode=REQUESTED_DATABASE_AUTH_MODE,
    runtime_profile=RUNTIME_PROFILE,
    is_postgres=_is_postgres,
)

if DATABASE_AUTH_MODE == "entra_token" and _is_postgres and _url_has_password(DATABASE_URL):
    if RUNTIME_PROFILE == RuntimeProfile.CLOUD_STRICT:
        raise ProductionDatabaseError(
            "cloud_strict profile blocks static PostgreSQL passwords. "
            "Use passwordless URL plus Entra token auth."
        )
    DATABASE_URL = _strip_password_from_database_url(DATABASE_URL)

connect_args = {"check_same_thread": False} if _is_sqlite else {}

_engine_kwargs: dict[str, Any] = {
    "echo": _env_flag("SQL_ECHO"),
    "connect_args": connect_args,
}

if _use_null_pool:
    _engine_kwargs["poolclass"] = NullPool
elif not _is_sqlite:
    uses_entra_token_auth = DATABASE_AUTH_MODE == "entra_token"
    DEFAULT_POOL_RECYCLE = (
        DEFAULT_TOKEN_POOL_RECYCLE_SECONDS
        if uses_entra_token_auth
        else DEFAULT_PASSWORD_POOL_RECYCLE_SECONDS
    )
    CONFIGURED_POOL_RECYCLE = _env_int("DATABASE_POOL_RECYCLE", DEFAULT_POOL_RECYCLE)

    _engine_kwargs["pool_size"] = _env_int("DATABASE_POOL_SIZE", 20)
    _engine_kwargs["max_overflow"] = _env_int("DATABASE_MAX_OVERFLOW", 40)
    _engine_kwargs["pool_timeout"] = _env_int("DATABASE_POOL_TIMEOUT", 30)
    _engine_kwargs["pool_recycle"] = _compute_pool_recycle_seconds(
        CONFIGURED_POOL_RECYCLE,
        token_auth_enabled=uses_entra_token_auth,
    )
    _engine_kwargs["pool_pre_ping"] = True

engine: AsyncEngine = create_async_engine(DATABASE_URL, **_engine_kwargs)

_token_provider: AzurePostgresTokenProvider | None = None
if DATABASE_AUTH_MODE == "entra_token" and _is_postgres:
    _token_provider = create_azure_postgres_token_provider(
        profile=RUNTIME_PROFILE,
        environment=_ENVIRONMENT,
    )
    _register_entra_token_pool_hooks(
        target_engine=engine,
        token_provider=_token_provider,
        min_ttl_seconds=_env_int(
            "DATABASE_TOKEN_EXPIRY_SAFETY_SECONDS",
            TOKEN_EXPIRY_WINDOW_SECONDS,
        ),
    )

# Async session factory
async_session_maker = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def _initialize_schema(conn: AsyncConnection) -> None:
    """Create all SQLModel tables on a single connection."""
    await conn.run_sync(SQLModel.metadata.create_all)


async def _init_postgresql_with_lock() -> None:
    """Initialize PostgreSQL schema with advisory lock to avoid worker races."""
    async with engine.begin() as conn:
        await conn.execute(
            text("SELECT pg_advisory_lock(:lock_id)"),
            {"lock_id": SCHEMA_INIT_LOCK_ID},
        )
        try:
            await _initialize_schema(conn)
        finally:
            await conn.execute(
                text("SELECT pg_advisory_unlock(:lock_id)"),
                {"lock_id": SCHEMA_INIT_LOCK_ID},
            )


async def init_db() -> None:
    """Create all tables asynchronously."""
    if _is_sqlite:
        async with engine.begin() as conn:
            await _initialize_schema(conn)
        return

    await _init_postgresql_with_lock()


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Async dependency for FastAPI routes."""
    async with async_session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


@asynccontextmanager
async def get_session_context() -> AsyncGenerator[AsyncSession, None]:
    """Async context manager for non-FastAPI usage."""
    async with async_session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def close_db() -> None:
    """Close database connections gracefully."""
    dispose_result = engine.dispose()
    if inspect.isawaitable(dispose_result):
        await dispose_result


class _SyncEngineSingleton:
    """Singleton for managing lazy-loaded synchronous engine instance."""

    _instance = None

    def __new__(cls):
        """Create singleton instance on first access."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize the singleton instance."""
        if not hasattr(self, "_engine"):
            self._engine = None

    def get_engine(self):
        """Get or create the synchronous engine."""
        if self._engine is None:
            sync_url = _to_sync_database_url(DATABASE_URL)
            self._engine = create_sync_engine(
                sync_url,
                connect_args={"check_same_thread": False} if _is_sqlite else {},
                echo=_env_flag("SQL_ECHO"),
            )
            if DATABASE_AUTH_MODE == "entra_token" and _is_postgres and _token_provider is not None:
                _register_sync_entra_token_pool_hooks(
                    target_engine=self._engine,
                    token_provider=_token_provider,
                    min_ttl_seconds=_env_int(
                        "DATABASE_TOKEN_EXPIRY_SAFETY_SECONDS",
                        TOKEN_EXPIRY_WINDOW_SECONDS,
                    ),
                )
        return self._engine


def get_sync_engine():
    """Lazy-load the synchronous engine. Only needed for migrations/CLI tools."""
    return _SyncEngineSingleton().get_engine()


def get_sync_session():
    """Synchronous session for migrations and CLI tools."""
    with Session(get_sync_engine()) as session:
        yield session


def init_db_sync() -> None:
    """Synchronous database initialization for migrations."""
    SQLModel.metadata.create_all(get_sync_engine())
