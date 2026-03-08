"""Shared SQLite fixture helpers for FastAPI and SQLModel tests."""

from __future__ import annotations

from collections.abc import Generator
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool


def in_memory_session() -> Generator[Session, None, None]:
    """Yield an isolated in-memory SQLModel session."""
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


def client_with_session_override(
    app: FastAPI,
    dependency: Any,
    session: Session,
) -> Generator[TestClient, None, None]:
    """Yield a TestClient with a session dependency override installed."""

    def get_session_override() -> Session:
        """Return the shared test session."""
        return session

    app.dependency_overrides[dependency] = get_session_override
    client = TestClient(app)
    try:
        yield client
    finally:
        app.dependency_overrides.clear()
