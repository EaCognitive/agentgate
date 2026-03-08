"""Shared fixtures for authorization-focused security tests."""

import os
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import User
from server.routers.auth_utils import _get_password_hash_sync as get_password_hash
from tests.security.security_test_support import app_client, in_memory_session

os.environ["REDIS_URL"] = "memory://"

ADMIN_PASSWORD = "adminpass123"
VIEWER_PASSWORD = "viewerpass123"
USER_PASSWORD = "userpass123"


def _create_user(session: Session, email: str, name: str, password: str, role: str) -> User:
    """Create and persist a user record for security tests."""
    user = User(
        email=email,
        name=name,
        hashed_password=get_password_hash(password),
        role=role,
        is_active=True,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def _login_for_token(client: TestClient, email: str, password: str) -> str:
    """Authenticate a seeded user and return its access token."""
    response = client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


@pytest.fixture(name="session")
def session_fixture() -> Generator[Session, None, None]:
    """Create an isolated in-memory database session."""
    with in_memory_session() as session:
        yield session


@pytest.fixture(name="client")
def client_fixture(session: Session) -> Generator[TestClient, None, None]:
    """Create a test client with DB overrides and disabled auth rate limiting."""
    with app_client(session, disable_main_limiter=False) as client:
        yield client


@pytest.fixture(name="admin_user")
def admin_user_fixture(session: Session) -> User:
    """Create an admin user."""
    return _create_user(session, "admin@example.com", "Admin User", ADMIN_PASSWORD, "admin")


@pytest.fixture(name="viewer_user")
def viewer_user_fixture(session: Session) -> User:
    """Create a viewer user."""
    return _create_user(session, "viewer@example.com", "Viewer User", VIEWER_PASSWORD, "viewer")


@pytest.fixture(name="user_a")
def user_a_fixture(session: Session) -> User:
    """Create the first developer user."""
    return _create_user(session, "usera@example.com", "User A", USER_PASSWORD, "developer")


@pytest.fixture(name="user_b")
def user_b_fixture(session: Session) -> User:
    """Create the second developer user."""
    return _create_user(session, "userb@example.com", "User B", USER_PASSWORD, "developer")


@pytest.fixture(name="admin_token")
def admin_token_fixture(client: TestClient, admin_user: User) -> str:
    """Return an access token for the admin user."""
    _ = admin_user
    return _login_for_token(client, "admin@example.com", ADMIN_PASSWORD)


@pytest.fixture(name="viewer_token")
def viewer_token_fixture(client: TestClient, viewer_user: User) -> str:
    """Return an access token for the viewer user."""
    _ = viewer_user
    return _login_for_token(client, "viewer@example.com", VIEWER_PASSWORD)


@pytest.fixture(name="user_a_token")
def user_a_token_fixture(client: TestClient, user_a: User) -> str:
    """Return an access token for developer user A."""
    _ = user_a
    return _login_for_token(client, "usera@example.com", USER_PASSWORD)


@pytest.fixture(name="user_b_token")
def user_b_token_fixture(client: TestClient, user_b: User) -> str:
    """Return an access token for developer user B."""
    _ = user_b
    return _login_for_token(client, "userb@example.com", USER_PASSWORD)
