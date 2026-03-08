"""Shared fixtures for SQL injection security tests."""

import os
from collections.abc import Generator
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import Approval, ApprovalStatus, Dataset, User
from server.routers.auth_utils import _get_password_hash_sync as get_password_hash
from tests.security.security_test_support import app_client, in_memory_session

os.environ["REDIS_URL"] = "memory://"

TEST_EMAIL = "test@example.com"
TEST_PASSWORD = "password123"


def _create_test_user(session: Session) -> User:
    """Create the shared authenticated user for SQL injection tests."""
    user = User(
        email=TEST_EMAIL,
        name="Test User",
        hashed_password=get_password_hash(TEST_PASSWORD),
        role="admin",
        is_active=True,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def _login_for_token(client: TestClient) -> str:
    """Authenticate the shared test user and return an access token."""
    response = client.post(
        "/api/auth/login",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


@pytest.fixture(name="session")
def session_fixture() -> Generator[Session, None, None]:
    """Create an isolated in-memory SQLite session."""
    with in_memory_session() as session:
        yield session


@pytest.fixture(name="client")
def client_fixture(session: Session) -> Generator[TestClient, None, None]:
    """Create a test client with DB overrides and rate limiting disabled."""
    with app_client(session, disable_main_limiter=True) as client:
        yield client


@pytest.fixture(name="test_user")
def test_user_fixture(session: Session) -> User:
    """Create the shared SQL-injection test user."""
    return _create_test_user(session)


@pytest.fixture(name="auth_token")
def auth_token_fixture(client: TestClient, test_user: User) -> str:
    """Return an access token for the shared SQL-injection test user."""
    _ = test_user
    return _login_for_token(client)


@pytest.fixture(name="test_approval")
def test_approval_fixture(session: Session) -> Approval:
    """Create a test approval in the database."""
    approval = Approval(
        approval_id="approval-123",
        agent_id="agent-1",
        tool="delete_file",
        inputs={"path": "/test/file.txt"},
        status=ApprovalStatus.PENDING,
        created_at=datetime.now(timezone.utc),
    )
    session.add(approval)
    session.commit()
    session.refresh(approval)
    return approval


@pytest.fixture(name="test_dataset")
def test_dataset_fixture(session: Session, test_user: User) -> Dataset:
    """Create a test dataset owned by the shared test user."""
    _ = test_user
    dataset = Dataset(
        name="Test Dataset",
        description="Test dataset for SQL injection tests",
        created_by=test_user.id,
    )
    session.add(dataset)
    session.commit()
    session.refresh(dataset)
    return dataset
