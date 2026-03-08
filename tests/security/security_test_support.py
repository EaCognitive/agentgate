"""Shared utilities for security test fixtures."""

from collections.abc import Generator
from contextlib import contextmanager
from importlib import import_module

from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

from server.main import app
from server.models import get_session
from server.routers import auth


@contextmanager
def in_memory_session() -> Generator[Session, None, None]:
    """Yield an isolated in-memory SQLite session."""
    import_module("server.models.formal_security_schemas")
    import_module("server.mcp.job_store")

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


@contextmanager
def app_client(session: Session, disable_main_limiter: bool) -> Generator[TestClient, None, None]:
    """Yield a test client with DB overrides and temporarily disabled rate limiting."""

    def get_session_override() -> Session:
        return session

    app.dependency_overrides[get_session] = get_session_override
    original_auth_enabled = auth.limiter.enabled
    auth.limiter.enabled = False
    original_main_enabled = None
    if disable_main_limiter:
        original_main_enabled = app.state.limiter.enabled
        app.state.limiter.enabled = False
    try:
        yield TestClient(app)
    finally:
        auth.limiter.enabled = original_auth_enabled
        if disable_main_limiter and original_main_enabled is not None:
            app.state.limiter.enabled = original_main_enabled
        app.dependency_overrides.clear()
