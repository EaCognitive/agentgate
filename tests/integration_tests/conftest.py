"""Integration test configuration and fixtures."""

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlmodel import Session, select

# Important: setup_env must be imported before server modules
# to ensure environment variables are configured correctly.
from tests.integration_tests import setup_env
from tests.integration_support import (
    build_common_fixtures,
)

from server.models import User, get_session
from server.routers import (
    approvals_router,
    audit_router,
    auth_mfa_router,
    auth_router,
    datasets_router,
    pii_compliance_router,
    pii_router,
    policies_router,
    policy_governance_router,
    settings_router,
    traces_router,
    users_router,
    verification_router,
)
from server.routers.auth_utils import _get_password_hash_sync as get_password_hash

# Prevent unused import warning
_ = setup_env

ROUTER_SPECS = (
    (auth_router, "/api"),
    (auth_mfa_router, "/api"),
    (pii_router, "/api"),
    (pii_compliance_router, "/api/pii"),
    (policy_governance_router, "/api"),
    (policies_router, "/api"),
    (audit_router, "/api"),
    (approvals_router, "/api"),
    (datasets_router, "/api"),
    (users_router, "/api"),
    (settings_router, "/api"),
    (verification_router, "/api"),
    (traces_router, "/api"),
)

(
    test_engine_fixture,
    test_app_fixture,
    auth_token_fixture,
    admin_token_fixture,
    session_fixture,
    client_fixture,
    auth_headers_fixture,
    admin_headers_fixture,
) = build_common_fixtures(ROUTER_SPECS)


@pytest.fixture(name="async_session")
async def async_session_fixture(test_engine):
    """Create async session for async tests.

    Note: This uses the sync engine but wrapped for async compatibility.
    For true async operations, use AsyncSession with async engine.
    """
    with Session(test_engine) as session:
        yield session
        session.rollback()


@pytest.fixture
async def async_client(test_app: FastAPI, async_session: Session):
    """Create async test client for async API tests.

    Uses httpx.AsyncClient with ASGI transport for true async testing.
    """

    def get_session_override() -> Session:
        return async_session

    test_app.dependency_overrides[get_session] = get_session_override

    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

    test_app.dependency_overrides.clear()


@pytest.fixture
async def test_user(async_session: Session):
    """Create test user for async tests."""

    user = async_session.exec(select(User).where(User.email == "asynctest@example.com")).first()

    if not user:
        user = User(
            email="asynctest@example.com",
            name="Async Test User",
            role="developer",
            hashed_password=get_password_hash("TestPass123!"),
        )
        async_session.add(user)
        async_session.commit()
        async_session.refresh(user)

    return user
