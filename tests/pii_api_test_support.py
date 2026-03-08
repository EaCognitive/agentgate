"""Shared fixtures for PII router endpoint tests."""

import asyncio
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlmodel import Session, SQLModel, create_engine

from server.main import app
from server.models import User, get_session
from server.routers.auth_utils import _get_password_hash_sync as get_password_hash

ADMIN_EMAIL = "admin@example.com"
ADMIN_NAME = "Admin User"
ADMIN_PASSWORD = "admin123"
REGULAR_EMAIL = "user@example.com"
REGULAR_NAME = "Regular User"
REGULAR_PASSWORD = "user123"


def _dispose_async_engine(async_engine) -> None:
    """Dispose an async SQLAlchemy engine from sync pytest fixtures."""
    try:
        asyncio.run(async_engine.dispose())
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(async_engine.dispose())
        finally:
            loop.close()


def _create_user(session: Session, email: str, name: str, password: str, role: str) -> User:
    """Create and persist a test user."""
    user = User(
        email=email,
        name=name,
        hashed_password=get_password_hash(password),
        role=role,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def _login_for_token(client: TestClient, email: str, password: str) -> str:
    """Return an access token for the supplied user credentials."""
    response = client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
    )
    return response.json()["access_token"]


@pytest.fixture(name="db_path")
def db_path_fixture(tmp_path) -> str:
    """Provide a temp file path for SQLite shared by sync and async engines."""
    return str(tmp_path / "test.db")


@pytest.fixture(name="session")
def session_fixture(db_path: str) -> Generator[Session, None, None]:
    """Create a sync test session for data seeding."""
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    SQLModel.metadata.create_all(engine)
    session = Session(engine)
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture(name="client")
def client_fixture(session: Session, db_path: str) -> Generator[TestClient, None, None]:
    """Create a test client backed by an async session override."""
    _ = session
    async_engine = create_async_engine(
        f"sqlite+aiosqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    session_factory = async_sessionmaker(
        async_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async def get_session_override():
        async with session_factory() as async_session:
            try:
                yield async_session
                await async_session.commit()
            except Exception:
                await async_session.rollback()
                raise

    app.dependency_overrides[get_session] = get_session_override
    client = TestClient(app)
    try:
        yield client
    finally:
        app.dependency_overrides.clear()
        _dispose_async_engine(async_engine)


@pytest.fixture(name="admin_user")
def admin_user_fixture(session: Session) -> User:
    """Create an admin user."""
    return _create_user(session, ADMIN_EMAIL, ADMIN_NAME, ADMIN_PASSWORD, "admin")


@pytest.fixture(name="regular_user")
def regular_user_fixture(session: Session) -> User:
    """Create a regular user."""
    return _create_user(session, REGULAR_EMAIL, REGULAR_NAME, REGULAR_PASSWORD, "user")


@pytest.fixture(name="admin_token")
def admin_token_fixture(client: TestClient, admin_user: User) -> str:
    """Return an access token for the seeded admin user."""
    _ = admin_user
    return _login_for_token(client, ADMIN_EMAIL, ADMIN_PASSWORD)


@pytest.fixture(name="user_token")
def user_token_fixture(client: TestClient, regular_user: User) -> str:
    """Return an access token for the seeded regular user."""
    _ = regular_user
    return _login_for_token(client, REGULAR_EMAIL, REGULAR_PASSWORD)
