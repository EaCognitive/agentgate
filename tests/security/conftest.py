"""
Pytest configuration for security tests.

This module provides fixtures and configuration for security testing.
Individual test files disable rate limiting via app.state.limiter.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from server.models import User
from server.routers.auth_utils import _get_password_hash_sync as get_password_hash


DEFAULT_TEST_EMAIL = "test@example.com"
DEFAULT_TEST_PASSWORD = "password123"
SECURITY_AUTH_EMAIL = "security-auth@example.com"
SECURITY_AUTH_PASSWORD = "SecurePass123!"
SECURITY_ADMIN_EMAIL = "security-admin@example.com"
SECURITY_ADMIN_PASSWORD = "AdminPass123!"


def _ensure_user(
    session: Session,
    *,
    email: str,
    name: str,
    password: str,
    role: str,
) -> User:
    """Create or update a security-suite user in the active test session."""
    user = session.exec(select(User).where(User.email == email)).one_or_none()
    hashed_password = get_password_hash(password)
    if user is None:
        user = User(
            email=email,
            name=name,
            hashed_password=hashed_password,
            role=role,
            is_active=True,
        )
        session.add(user)
    else:
        user.name = name
        user.hashed_password = hashed_password
        user.role = role
        user.is_active = True
        session.add(user)
    session.commit()
    session.refresh(user)
    return user


def _login_headers(client: TestClient, *, email: str, password: str) -> dict[str, str]:
    """Log in through the API and return bearer authorization headers."""
    response = client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
    )
    assert response.status_code == 200, response.text
    access_token = response.json()["access_token"]
    return {"Authorization": f"Bearer {access_token}"}


@pytest.fixture(scope="session", autouse=True)
def setup_path():
    """Ensure the project root is in the Python path."""
    project_root = Path(__file__).parent.parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    yield


@pytest.fixture(name="test_user")
def test_user_fixture(session: Session) -> User:
    """Provide a default security-suite user in the active session."""
    return _ensure_user(
        session,
        email=DEFAULT_TEST_EMAIL,
        name="Security Test User",
        password=DEFAULT_TEST_PASSWORD,
        role="admin",
    )


@pytest.fixture(name="auth_headers")
def auth_headers_fixture(client: TestClient, session: Session) -> dict[str, str]:
    """Provide auth headers backed by the same client/session pair under test."""
    _ensure_user(
        session,
        email=SECURITY_AUTH_EMAIL,
        name="Security Auth User",
        password=SECURITY_AUTH_PASSWORD,
        role="admin",
    )
    return _login_headers(
        client,
        email=SECURITY_AUTH_EMAIL,
        password=SECURITY_AUTH_PASSWORD,
    )


@pytest.fixture(name="admin_headers")
def admin_headers_fixture(client: TestClient, session: Session) -> dict[str, str]:
    """Provide admin headers backed by the same client/session pair under test."""
    _ensure_user(
        session,
        email=SECURITY_ADMIN_EMAIL,
        name="Security Admin User",
        password=SECURITY_ADMIN_PASSWORD,
        role="admin",
    )
    return _login_headers(
        client,
        email=SECURITY_ADMIN_EMAIL,
        password=SECURITY_ADMIN_PASSWORD,
    )
