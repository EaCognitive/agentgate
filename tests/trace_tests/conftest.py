"""Shared fixtures for trace tests."""

from datetime import datetime, timezone
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

from server.main import app
from server.models import Trace, TraceStatus, User, UserRole, get_session
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


@pytest.fixture(name="admin_token")
def admin_token_fixture(client: TestClient, admin_user: User) -> str:
    """Get admin access token."""
    assert admin_user.id is not None
    response = client.post(
        "/api/auth/login",
        json={
            "email": "admin@example.com",
            "password": "password123",
        },
    )
    assert response.status_code == 200
    return response.json()["access_token"]


@pytest.fixture(name="viewer_token")
def viewer_token_fixture(client: TestClient, viewer_user: User) -> str:
    """Get viewer access token."""
    assert viewer_user.id is not None
    response = client.post(
        "/api/auth/login",
        json={
            "email": "viewer@example.com",
            "password": "password123",
        },
    )
    assert response.status_code == 200
    return response.json()["access_token"]


@pytest.fixture(name="test_trace")
def test_trace_fixture(session: Session) -> Trace:
    """Create a sample trace."""
    trace = Trace(
        trace_id="test_trace",
        tool="test_tool",
        status=TraceStatus.SUCCESS,
        inputs={"key": "value"},
        output={"result": "ok"},
        duration_ms=100.0,
        cost=0.01,
        started_at=datetime.now(timezone.utc),
    )
    session.add(trace)
    session.commit()
    session.refresh(trace)
    return trace
