"""Pytest fixtures for agentgate tests."""

import asyncio
from importlib import import_module
import os
import signal
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
import pytest
from dotenv import load_dotenv
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel, select

# Ensure test-mode environment variables are set before importing server modules.
from tests.integration_tests import setup_env as _integration_setup_env

from ea_agentgate.agent import Agent
from ea_agentgate.middleware.cost_tracker import CostTracker
from ea_agentgate.middleware.rate_limiter import RateLimiter
from server.models import User, get_session
from server.routers import (
    auth_router,
    pii_router,
    policies_router,
    policy_governance_router,
)
from server.routers.auth_utils import (
    _get_password_hash_sync as get_password_hash,
)
from server.routers.auth_utils import (
    _SecretKeyHolder,
    get_secret_key,
)
from server.utils.db import (
    commit as db_commit,
)
from server.utils.db import (
    execute as db_execute,
)
from server.utils.db import (
    refresh as db_refresh,
)

_ = _integration_setup_env
pytest_plugins = ("tests.router_test_support",)

# Load environment variables from .env file
env_path = Path(__file__).parent.parent / ".env"
if env_path.exists():
    load_dotenv(env_path)


# Set SECRET_KEY for JWT encoding/decoding in tests
os.environ["SECRET_KEY"] = "dev-secret-key-for-local-development-only-32chars"

# Clear OpenTelemetry config that conflicts with ddtrace (if present)
# This prevents the warning:
# "OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE is not supported by Datadog"
os.environ.pop("OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE", None)

# Configure test environment
os.environ["TESTING"] = "true"
os.environ["ENABLE_THREAT_DETECTION"] = "false"
os.environ["REDIS_URL"] = "memory://"


_FORMAL_WORKER_MARKERS = (
    "spawn_main(tracker_fd=",
    "multiprocessing.resource_tracker",
    "loky.process_executor",
    "joblib.externals.loky",
    "python -m server.mcp",
)


def _is_pid_alive(pid: int) -> bool:
    """Return whether a process ID is still alive."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return False
    return True


def _collect_formal_worker_pids() -> list[int]:
    """Collect orphaned worker process IDs from prior heavy formal tests."""
    try:
        result = subprocess.run(
            ["ps", "-axo", "pid=,command="],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return []

    if result.returncode != 0:
        return []

    own_pid = os.getpid()
    parent_pid = os.getppid()
    pids: list[int] = []
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        pid_text, command = parts
        if not pid_text.isdigit():
            continue
        pid = int(pid_text)
        if pid in {own_pid, parent_pid}:
            continue
        if any(marker in command for marker in _FORMAL_WORKER_MARKERS):
            pids.append(pid)
    return pids


def _terminate_formal_workers() -> None:
    """Terminate orphaned formal workers to prevent multi-core runaway processes."""
    pids = _collect_formal_worker_pids()
    if not pids:
        return

    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            continue
        except PermissionError:
            continue
    time.sleep(0.5)

    for pid in pids:
        if not _is_pid_alive(pid):
            continue
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            continue
        except PermissionError:
            continue


def pytest_sessionstart(session) -> None:
    """Clear orphaned heavy formal workers before starting test collection."""
    del session
    _terminate_formal_workers()


def is_docker_available() -> bool:
    """Check if Docker is available and running."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def is_postgres_test_container_running() -> bool:
    """Check if the PostgreSQL test container is already running."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=agentgate-db-test-1", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return "db-test" in result.stdout
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def start_postgres_test_container() -> bool:
    """Start the PostgreSQL test container using docker compose."""
    try:
        result = subprocess.run(
            ["docker", "compose", "--profile", "test", "up", "-d", "db-test"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if result.returncode != 0:
            return False

        # Wait for container to be healthy
        for _ in range(30):
            check = subprocess.run(
                [
                    "docker",
                    "compose",
                    "--profile",
                    "test",
                    "exec",
                    "-T",
                    "db-test",
                    "pg_isready",
                    "-U",
                    "test",
                ],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if check.returncode == 0:
                return True
            time.sleep(1)
        return False
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def stop_postgres_test_container() -> None:
    """Stop the PostgreSQL test container."""
    try:
        subprocess.run(
            ["docker", "compose", "--profile", "test", "down", "db-test"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        pass


@pytest.fixture(scope="session")
def postgres_test_db():
    """Session-scoped fixture that manages PostgreSQL test container.

    Yields the database URL if PostgreSQL is available, None otherwise.
    """
    test_url = os.getenv("TEST_DATABASE_URL")
    if test_url:
        yield test_url
        return

    if not is_docker_available():
        yield None
        return

    container_started = False
    if not is_postgres_test_container_running():
        if start_postgres_test_container():
            container_started = True
            os.environ["TEST_DATABASE_URL"] = "postgresql://test:test@localhost:5433/test_agentgate"
    else:
        os.environ["TEST_DATABASE_URL"] = "postgresql://test:test@localhost:5433/test_agentgate"

    yield os.getenv("TEST_DATABASE_URL")

    if container_started:
        stop_postgres_test_container()


@pytest.fixture
def basic_agent():
    """Create a basic agent with no middleware."""
    return Agent()


@pytest.fixture
def agent_with_rate_limiter():
    """Create an agent with rate limiting."""
    return Agent(middleware=[RateLimiter(max_calls=60, window="1m")])


@pytest.fixture
def agent_with_cost_tracker():
    """Create an agent with cost tracking."""
    return Agent(middleware=[CostTracker(max_budget=100.0)])


@pytest.fixture(scope="session", autouse=True)
def close_async_engine_session():
    """Ensure global async engine is disposed at the end of the test run."""
    yield
    try:
        database = import_module("server.models.database")
    except ImportError:
        return
    try:
        asyncio.run(database.close_db())
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(database.close_db())
        finally:
            loop.close()
    policy = asyncio.get_event_loop_policy()
    stored_loop = getattr(getattr(policy, "_local", None), "loop", None)
    if stored_loop and not stored_loop.is_closed():
        try:
            stored_loop.run_until_complete(asyncio.sleep(0))
        except RuntimeError:
            pass


def pytest_sessionfinish(session, exitstatus) -> None:
    """Close any event loops left open after the suite."""
    del session, exitstatus
    policy = asyncio.get_event_loop_policy()
    candidate = getattr(getattr(policy, "_local", None), "loop", None)
    if candidate and not candidate.is_closed():
        try:
            candidate.run_until_complete(candidate.shutdown_asyncgens())
        except RuntimeError:
            pass
        candidate.close()
        policy.set_event_loop(None)
    try:
        current = asyncio.get_running_loop()
    except RuntimeError:
        current = None
    if current and not current.is_closed():
        try:
            current.run_until_complete(asyncio.sleep(0))
        except RuntimeError:
            pass
        current.close()
        policy.set_event_loop(None)
    _terminate_formal_workers()


@pytest.fixture
def sample_tool():
    """A simple tool function for testing."""

    def read_file(path: str) -> str:
        return f"Contents of {path}"

    return read_file


@pytest.fixture
def failing_tool():
    """A tool that always fails."""

    def fail_tool():
        raise ValueError("Tool failed")

    return fail_tool


# ============================================================================
# Async Testing Fixtures
# ============================================================================


@pytest.fixture(name="async_session")
async def async_session_fixture():
    """Create async session for async tests."""

    # Register runtime governance tables required by isolated MCP/security tests.
    import_module("server.models.formal_security_schemas")
    import_module("server.mcp.job_store")

    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    async_session_maker = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session_maker() as session:
        try:
            yield session
        finally:
            await session.rollback()
    await engine.dispose()


@pytest.fixture
async def async_client(async_session):
    """Create async test client for async API tests."""

    # Reset secret key cache to ensure it picks up the test env var
    _SecretKeyHolder.reset()

    app = FastAPI(title="Test App")
    app.include_router(auth_router, prefix="/api")
    app.include_router(pii_router, prefix="/api")
    app.include_router(policy_governance_router, prefix="/api")
    app.include_router(policies_router, prefix="/api")

    def get_session_override():
        return async_session

    # Use real JWT auth instead of mocking
    app.dependency_overrides[get_session] = get_session_override

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

    # Cleanup
    app.dependency_overrides.clear()


@pytest.fixture
async def test_user(async_session):
    """Create test user for async tests."""

    result = await db_execute(
        async_session, select(User).where(User.email == "asynctest@example.com")
    )
    user = result.scalar_one_or_none()

    if not user:
        user = User(
            email="asynctest@example.com",
            name="Async Test User",
            role="developer",
            hashed_password=get_password_hash("TestPass123!"),
        )
        async_session.add(user)
        await db_commit(async_session)
        await db_refresh(async_session, user)

    return user


@pytest.fixture
async def admin_headers(async_session):
    """Return admin headers for async tests."""

    result = await db_execute(async_session, select(User).where(User.email == "admin@admin.com"))
    admin = result.scalar_one_or_none()
    if not admin:
        admin = User(
            email="admin@admin.com",
            name="Admin User",
            role="admin",
            hashed_password=get_password_hash("password"),
        )
        async_session.add(admin)
        await db_commit(async_session)
        await db_refresh(async_session, admin)

    payload = {
        "sub": admin.email,  # get_current_user looks up by email from 'sub'
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
    }
    token = jwt.encode(payload, get_secret_key(), algorithm="HS256")

    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
async def auth_headers(async_session):
    """Return auth headers for regular user in async tests."""

    result = await db_execute(
        async_session, select(User).where(User.email == "asynctest@example.com")
    )
    user = result.scalar_one_or_none()
    if not user:
        user = User(
            email="asynctest@example.com",
            name="Async Test User",
            role="developer",
            hashed_password=get_password_hash("TestPass123!"),
        )
        async_session.add(user)
        await db_commit(async_session)
        await db_refresh(async_session, user)

    payload = {
        "sub": user.email,  # get_current_user looks up by email from 'sub'
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
    }
    token = jwt.encode(payload, get_secret_key(), algorithm="HS256")

    return {"Authorization": f"Bearer {token}"}
