"""
Shared fixtures for dataset tests.
"""

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

from server.main import app
from server.models import (
    Dataset,
    Trace,
    TraceStatus,
    User,
    UserRole,
    get_session,
)
from server.routers.auth import create_access_token
from server.routers.auth_utils import _get_password_hash_sync as get_password_hash


@pytest.fixture(name="session")
def session_fixture() -> Generator[Session, None, None]:
    """Create test database session with all tables."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    session = Session(engine)
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture(name="client")
def client_fixture(session: Session) -> Generator[TestClient, None, None]:
    """Create test client with dependency override."""

    def get_session_override() -> Session:
        return session

    app.dependency_overrides[get_session] = get_session_override
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


@pytest.fixture(name="admin_user")
def admin_user_fixture(session: Session) -> User:
    """Create admin user for testing."""

    user = User(
        email="admin@example.com",
        name="Admin User",
        hashed_password=get_password_hash("password123"),
        role=UserRole.ADMIN,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@pytest.fixture(name="viewer_user")
def viewer_user_fixture(session: Session) -> User:
    """Create viewer user for testing RBAC."""

    user = User(
        email="viewer@example.com",
        name="Viewer User",
        hashed_password=get_password_hash("password123"),
        role=UserRole.VIEWER,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@pytest.fixture(name="developer_user")
def developer_user_fixture(session: Session) -> User:
    """Create developer user for testing RBAC."""

    user = User(
        email="developer@example.com",
        name="Developer User",
        hashed_password=get_password_hash("password123"),
        role=UserRole.DEVELOPER,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@pytest.fixture(name="admin_token")
def admin_token_fixture(admin_user: User) -> str:
    """Get admin access token (bypassing login to avoid rate limits)."""

    return create_access_token({"sub": admin_user.email})


@pytest.fixture(name="viewer_token")
def viewer_token_fixture(viewer_user: User) -> str:
    """Get viewer access token (bypassing login to avoid rate limits)."""

    return create_access_token({"sub": viewer_user.email})


@pytest.fixture(name="developer_token")
def developer_token_fixture(developer_user: User) -> str:
    """Get developer access token (bypassing login to avoid rate limits)."""

    return create_access_token({"sub": developer_user.email})


@pytest.fixture(name="test_dataset")
def test_dataset_fixture(session: Session, admin_user: User) -> Dataset:
    """Create a test dataset."""
    dataset = Dataset(
        name="Test Dataset",
        description="A test dataset",
        tags=["test"],
        created_by=admin_user.id,
    )
    session.add(dataset)
    session.commit()
    session.refresh(dataset)
    return dataset


@pytest.fixture(name="test_trace")
def test_trace_fixture(session: Session) -> Trace:
    """Create a successful trace for testing."""
    trace = Trace(
        trace_id="trace_success_123",
        tool="api_call",
        inputs={"url": "https://api.example.com"},
        output={"status": 200, "data": "success"},
        status=TraceStatus.SUCCESS,
        duration_ms=150.5,
        cost=0.002,
    )
    session.add(trace)
    session.commit()
    session.refresh(trace)
    return trace
