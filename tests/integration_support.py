"""Shared helpers for integration test app and auth fixture setup."""

from __future__ import annotations

import time
from collections.abc import Generator, Iterable
from typing import Any

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
from slowapi import Limiter
from slowapi.util import get_ipaddr
from sqlmodel import Session, SQLModel, create_engine, select
from sqlmodel.pool import StaticPool

from server.models import User, get_session


def create_rate_limited_test_app(
    router_specs: Iterable[tuple[APIRouter, str]],
    *,
    title: str = "AgentGate Test API",
) -> FastAPI:
    """Create a FastAPI test app with a permissive in-memory rate limiter."""
    test_app = FastAPI(title=title)
    test_app.state.limiter = Limiter(
        key_func=get_ipaddr,
        storage_uri="memory://",
        default_limits=["100000/minute"],
    )
    for router, prefix in router_specs:
        test_app.include_router(router, prefix=prefix)
    return test_app


def create_test_engine() -> Any:
    """Create a shared in-memory SQLModel engine for integration tests."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    return engine


def issue_session_token(
    test_app: FastAPI,
    test_engine: Any,
    *,
    email: str,
    password: str,
    name: str,
    ensure_admin: bool = False,
) -> str:
    """Create a user when needed and return a bearer token."""
    with Session(test_engine) as session:
        user = session.exec(select(User).where(User.email == email)).first()

        def get_session_override() -> Session:
            return session

        test_app.dependency_overrides[get_session] = get_session_override
        client = TestClient(test_app)

        if not user:
            response = client.post(
                "/api/auth/register",
                json={
                    "email": email,
                    "password": password,
                    "name": name,
                },
            )
            time.sleep(0.1)
            if ensure_admin:
                user = session.exec(select(User).where(User.email == email)).first()
                if user and user.role != "admin":
                    user.role = "admin"
                    session.add(user)
                    session.commit()

        response = client.post(
            "/api/auth/login",
            json={
                "email": email,
                "password": password,
            },
        )
        test_app.dependency_overrides.clear()

        if response.status_code != 200:
            pytest.fail(f"Login failed: {response.status_code} - {response.text}")

        return response.json()["access_token"]


def session_scope(test_engine: Any) -> Generator[Session, None, None]:
    """Yield a SQLModel session and roll it back after each test."""
    with Session(test_engine) as session:
        yield session
        session.rollback()


def client_scope(
    session: Session,
    test_app: FastAPI,
) -> Generator[TestClient, None, None]:
    """Yield a test client bound to the provided database session."""

    def get_session_override() -> Session:
        return session

    test_app.dependency_overrides[get_session] = get_session_override
    client = TestClient(test_app)
    yield client
    test_app.dependency_overrides.clear()


def bearer_headers(token: str) -> dict[str, str]:
    """Build standard Authorization headers for a bearer token."""
    return {"Authorization": f"Bearer {token}"}


def build_common_fixtures(router_specs: Iterable[tuple[APIRouter, str]]) -> tuple[Any, ...]:
    """Build shared integration fixtures for a specific router set."""

    @pytest.fixture(name="test_engine", scope="session")
    def test_engine_fixture():
        """Create test database engine for entire test session."""
        return create_test_engine()

    @pytest.fixture(name="test_app", scope="session")
    def test_app_fixture() -> FastAPI:
        """Create FastAPI app instance once per session."""
        return create_rate_limited_test_app(router_specs)

    @pytest.fixture(name="auth_token", scope="session")
    def auth_token_fixture(test_app: FastAPI, test_engine: Any) -> str:
        """Create a shared auth token for integration tests."""
        return issue_session_token(
            test_app,
            test_engine,
            email="testuser@example.com",
            password="SecurePass123!",
            name="Test User",
        )

    @pytest.fixture(name="admin_token", scope="session")
    def admin_token_fixture(test_app: FastAPI, test_engine: Any) -> str:
        """Create a shared admin token for integration tests."""
        return issue_session_token(
            test_app,
            test_engine,
            email="admin@example.com",
            password="AdminPass123!",
            name="Admin User",
            ensure_admin=True,
        )

    @pytest.fixture(name="session", scope="function")
    def session_fixture(test_engine: Any) -> Generator[Session, None, None]:
        """Create test database session for each test."""
        yield from session_scope(test_engine)

    @pytest.fixture(name="client")
    def client_fixture(
        session: Session,
        test_app: FastAPI,
    ) -> Generator[TestClient, None, None]:
        """Create test client with database session override."""
        yield from client_scope(session, test_app)

    @pytest.fixture(name="auth_headers")
    def auth_headers_fixture(auth_token: str) -> dict[str, str]:
        """Return auth headers using session-scoped token."""
        return bearer_headers(auth_token)

    @pytest.fixture(name="admin_headers")
    def admin_headers_fixture(admin_token: str) -> dict[str, str]:
        """Return admin headers using session-scoped token."""
        return bearer_headers(admin_token)

    return (
        test_engine_fixture,
        test_app_fixture,
        auth_token_fixture,
        admin_token_fixture,
        session_fixture,
        client_fixture,
        auth_headers_fixture,
        admin_headers_fixture,
    )
