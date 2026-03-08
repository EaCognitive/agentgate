"""Shared fixtures for XSS and CSRF security tests."""

import os
from collections.abc import Generator

import bcrypt
import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import User
from tests.security.security_test_support import app_client, in_memory_session

os.environ["REDIS_URL"] = "memory://"

AUTH_EMAIL = "test@example.com"
AUTH_PASSWORD = "SecurePass123!"
ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "AdminPass123!"


def _create_user(session: Session, email: str, name: str, password: str) -> User:
    """Create and persist a test user with bcrypt hashing."""
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    user = User(
        email=email,
        name=name,
        hashed_password=hashed,
        role="admin",
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def _login_headers(client: TestClient, email: str, password: str) -> dict[str, str]:
    """Authenticate a test user and return bearer headers."""
    response = client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
    )
    assert response.status_code == 200, f"Login failed: {response.text}"
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture(name="xss_session", scope="module")
def xss_session_fixture() -> Generator[Session, None, None]:
    """Create a module-scoped in-memory database session."""
    with in_memory_session() as session:
        yield session


@pytest.fixture(name="xss_client", scope="module")
def xss_client_fixture(xss_session: Session) -> Generator[TestClient, None, None]:
    """Create a module-scoped client with DB overrides and disabled rate limiting."""
    with app_client(xss_session, disable_main_limiter=True) as client:
        yield client


@pytest.fixture(name="xss_auth_user", scope="module")
def xss_auth_user_fixture(xss_session: Session) -> User:
    """Create the primary authenticated user."""
    return _create_user(xss_session, AUTH_EMAIL, "Test User", AUTH_PASSWORD)


@pytest.fixture(name="xss_auth_headers", scope="module")
def xss_auth_headers_fixture(
    xss_client: TestClient,
    xss_auth_user: User,
) -> dict[str, str]:
    """Return bearer headers for the primary authenticated user."""
    _ = xss_auth_user
    return _login_headers(xss_client, AUTH_EMAIL, AUTH_PASSWORD)


@pytest.fixture(name="xss_admin_user", scope="module")
def xss_admin_user_fixture(xss_session: Session) -> User:
    """Create the admin user for admin-only endpoint checks."""
    return _create_user(xss_session, ADMIN_EMAIL, "Admin User", ADMIN_PASSWORD)


@pytest.fixture(name="xss_admin_headers", scope="module")
def xss_admin_headers_fixture(
    xss_client: TestClient,
    xss_admin_user: User,
) -> dict[str, str]:
    """Return bearer headers for the admin user."""
    _ = xss_admin_user
    return _login_headers(xss_client, ADMIN_EMAIL, ADMIN_PASSWORD)
