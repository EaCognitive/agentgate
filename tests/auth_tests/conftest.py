"""Shared fixtures for auth tests."""

from datetime import timedelta

import pytest
from sqlmodel import Session

from server.models import User
from tests.router_test_support import bearer_token, create_test_user


@pytest.fixture(name="test_user")
def test_user_fixture(session: Session):
    """Create a basic test user."""
    return create_test_user(
        session,
        email="extended@test.com",
        name="Extended Test",
        password="testpass123",
        role="developer",
        is_active=True,
    )


@pytest.fixture(name="inactive_user")
def inactive_user_fixture(session: Session):
    """Create an inactive test user."""
    return create_test_user(
        session,
        email="inactive@test.com",
        name="Inactive User",
        password="password123",
        role="viewer",
        is_active=False,
    )


@pytest.fixture(name="auth_token")
def auth_token_fixture(test_user: User):
    """Get auth token for test user."""
    return bearer_token(test_user, expires_delta=timedelta(minutes=15))
