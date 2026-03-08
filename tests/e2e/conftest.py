"""E2E test configuration -- boots the real server.main:app.

Environment variables MUST be set before any server.* import because
server.models.database reads DATABASE_URL at module level (line 25).

When pytest-xdist distributes tests, other conftest files (e.g.
auth_mfa_tests) may import server.models.database before this module
loads, causing the engine to point at the wrong database. The
e2e_client fixture re-initialises the engine to guarantee isolation.
"""

from importlib import import_module
import os
import shutil
import tempfile

import httpx
import pytest_asyncio
from httpx import ASGITransport
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

# ---------------------------------------------------------------------------
# 1. Create an isolated temp SQLite database
# ---------------------------------------------------------------------------
_tmpdir = tempfile.mkdtemp(prefix="agentgate_e2e_")
_db_path = os.path.join(_tmpdir, "e2e_test.db")
_DB_URL = f"sqlite+aiosqlite:///{_db_path}"

os.environ["DATABASE_URL"] = _DB_URL
os.environ["DATABASE_POOL_DISABLED"] = "1"  # NullPool avoids pool_size/SQLite issues
os.environ["TESTING"] = "true"
os.environ["AGENTGATE_ENV"] = "test"
os.environ["SECRET_KEY"] = "e2e-test-secret-key-must-be-at-least-32-chars!"
os.environ["REDIS_URL"] = "memory://"
os.environ["ENABLE_THREAT_DETECTION"] = "true"

app = import_module("server.main").app
_db_mod = import_module("server.models.database")

# ---------------------------------------------------------------------------
# 2. Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="session", name="e2e_client")
async def _e2e_client_impl():
    """Session-scoped async HTTP client wired to the real ASGI app.

    Manually triggers init_db/close_db because httpx ASGITransport
    does not invoke the ASGI lifespan by default.

    Re-creates the async engine so that it always points at the
    temporary e2e database, even when another conftest has already
    imported server.models.database with a different DATABASE_URL.
    """

    _db_mod.engine = create_async_engine(
        _DB_URL,
        connect_args={"check_same_thread": False},
        poolclass=NullPool,
    )
    _db_mod.async_session_maker = async_sessionmaker(
        _db_mod.engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )

    await _db_mod.init_db()
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
    ) as client:
        yield client
    await _db_mod.close_db()


@pytest_asyncio.fixture(scope="session", name="registered_admin")
async def _registered_admin_impl(e2e_client: httpx.AsyncClient):
    """Register the first user (auto-admin) and return credentials + token."""
    email = "admin-e2e@agentgate.test"
    password = "AdminE2E!Secure99"

    resp = await e2e_client.post(
        "/api/auth/register",
        json={
            "email": email,
            "password": password,
            "name": "E2E Admin",
        },
    )
    if resp.status_code != 200:
        assert resp.status_code == 400, f"Admin registration failed: {resp.text}"

    resp = await e2e_client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
    )
    assert resp.status_code == 200, f"Admin login failed: {resp.text}"
    data = resp.json()

    return {
        "email": email,
        "password": password,
        "access_token": data["access_token"],
        "refresh_token": data["refresh_token"],
        "headers": {"Authorization": f"Bearer {data['access_token']}"},
    }


@pytest_asyncio.fixture(scope="session", name="registered_user")
async def _registered_user_impl(e2e_client: httpx.AsyncClient, registered_admin):
    """Register a second user (auto-viewer) and return credentials + token."""
    _ = registered_admin  # Ensure admin exists first (first user = admin)
    email = "viewer-e2e@agentgate.test"
    password = "ViewerE2E!Secure99"

    resp = await e2e_client.post(
        "/api/auth/register",
        json={
            "email": email,
            "password": password,
            "name": "E2E Viewer",
        },
    )
    if resp.status_code != 200:
        assert resp.status_code == 400, f"Viewer registration failed: {resp.text}"

    resp = await e2e_client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
    )
    assert resp.status_code == 200, f"Viewer login failed: {resp.text}"
    data = resp.json()

    return {
        "email": email,
        "password": password,
        "access_token": data["access_token"],
        "refresh_token": data["refresh_token"],
        "headers": {"Authorization": f"Bearer {data['access_token']}"},
    }


def pytest_sessionfinish(session, exitstatus):
    """Remove the temporary database directory after the test session.

    Args:
        session: The pytest session object (required by pytest hook spec)
        exitstatus: The exit status code (required by pytest hook spec)
    """
    del session, exitstatus  # Required by pytest hook signature but unused
    shutil.rmtree(_tmpdir, ignore_errors=True)
