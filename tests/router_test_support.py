"""Shared fixtures and helpers for router-focused API tests."""

from collections.abc import Generator
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session
from sqlmodel import select

from server.main import app
from server.main import limiter as main_limiter
from server.models import User, get_session
from server.routers.auth import create_access_token
from server.routers.auth import limiter as auth_limiter
from server.routers.auth_utils import _get_password_hash_sync as get_password_hash
from tests.security.security_test_support import in_memory_session


def _resolve_tenant_id(
    tenant_id: str | None,
    *,
    existing_tenant_id: str | None = None,
) -> str:
    """Return a non-null tenant id for router-test users."""
    if tenant_id:
        return tenant_id
    if existing_tenant_id:
        return existing_tenant_id
    return "default"


def create_test_user(
    session: Session,
    *,
    email: str,
    name: str,
    password: str,
    role: str,
    tenant_id: str | None = None,
    **extra_fields,
) -> User:
    """Create and persist a router-test user."""
    user = session.exec(select(User).where(User.email == email)).one_or_none()
    if user is None:
        resolved_tenant_id = _resolve_tenant_id(tenant_id)
        user = User(
            email=email,
            name=name,
            hashed_password=get_password_hash(password),
            role=role,
            tenant_id=resolved_tenant_id,
            **extra_fields,
        )
    else:
        user.name = name
        user.hashed_password = get_password_hash(password)
        user.role = role
        user.tenant_id = _resolve_tenant_id(
            tenant_id,
            existing_tenant_id=user.tenant_id,
        )
        for field_name, field_value in extra_fields.items():
            setattr(user, field_name, field_value)
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def bearer_headers(
    user: User,
    *,
    assurance: str | None = None,
    expires_delta: timedelta | None = None,
) -> dict[str, str]:
    """Build bearer-token headers for a persisted user."""
    token_data = {"sub": user.email, "role": user.role}
    if assurance is not None:
        token_data["session_assurance"] = assurance
    token = create_access_token(
        data=token_data,
        expires_delta=expires_delta or timedelta(minutes=15),
    )
    return {"Authorization": f"Bearer {token}"}


def bearer_token(
    user: User,
    *,
    assurance: str | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    """Build a bare access token string for a persisted user."""
    return bearer_headers(
        user,
        assurance=assurance,
        expires_delta=expires_delta,
    )["Authorization"].removeprefix("Bearer ")


@pytest.fixture(scope="function", autouse=True)
def disable_rate_limiting() -> Generator[None, None, None]:
    """Disable API rate limits for deterministic router tests."""
    main_enabled = main_limiter.enabled
    auth_enabled = auth_limiter.enabled
    main_limiter.enabled = False
    auth_limiter.enabled = False
    try:
        yield
    finally:
        main_limiter.enabled = main_enabled
        auth_limiter.enabled = auth_enabled


@pytest.fixture(name="session")
def session_fixture() -> Generator[Session, None, None]:
    """Create an isolated in-memory SQLModel session."""
    with in_memory_session() as session:
        yield session


@pytest.fixture(name="client")
def client_fixture(session: Session) -> Generator[TestClient, None, None]:
    """Create a TestClient with a DB dependency override."""

    def get_session_override() -> Session:
        return session

    app.dependency_overrides[get_session] = get_session_override
    client = TestClient(app)
    try:
        yield client
    finally:
        app.dependency_overrides.clear()
