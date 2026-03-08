"""Tests for server trace endpoints."""

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import Trace, TraceStatus
from tests.simple_auth_flow_support import register_and_login

pytest_plugins = ("tests.router_test_support",)


@pytest.fixture(name="auth_token")
def auth_token_fixture(client: TestClient):
    """Create authenticated user and return token."""
    return register_and_login(
        client,
        email="test@example.com",
        password="password123",
        name="Test User",
    )


def test_create_trace(client: TestClient, auth_token: str):
    """Test creating a trace."""
    response = client.post(
        "/api/traces",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "trace_id": "trace_123",
            "tool": "calculator",
            "inputs": {"a": 1, "b": 2},
            "status": "success",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["trace_id"] == "trace_123"
    assert data["tool"] == "calculator"
    assert data["status"] == "success"


def test_list_traces_requires_auth(client: TestClient, auth_token: str):
    """Test listing traces requires authentication."""
    # Without auth should fail
    response = client.get("/api/traces")
    assert response.status_code == 401

    # With auth should succeed
    response = client.get(
        "/api/traces",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert response.status_code == 200


def test_list_traces(client: TestClient, auth_token: str, session: Session):
    """Test listing traces."""
    # Create some traces
    for i in range(3):
        trace = Trace(
            trace_id=f"trace_{i}",
            tool="calculator",
            status=TraceStatus.SUCCESS,
        )
        session.add(trace)
    session.commit()

    # List traces
    response = client.get(
        "/api/traces",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 3


def test_list_traces_filter_by_status(client: TestClient, auth_token: str, session: Session):
    """Test filtering traces by status."""
    # Create traces with different statuses
    session.add(Trace(trace_id="trace_1", tool="tool1", status=TraceStatus.SUCCESS))
    session.add(Trace(trace_id="trace_2", tool="tool2", status=TraceStatus.FAILED))
    session.add(Trace(trace_id="trace_3", tool="tool3", status=TraceStatus.SUCCESS))
    session.commit()

    # Filter by success
    response = client.get(
        "/api/traces?status=success",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    assert all(t["status"] == "success" for t in data)


def test_get_trace_by_id(client: TestClient, auth_token: str, session: Session):
    """Test getting a single trace by ID."""
    trace = Trace(
        trace_id="trace_123",
        tool="calculator",
        status=TraceStatus.SUCCESS,
        inputs={"a": 1, "b": 2},
        output={"result": 3},
    )
    session.add(trace)
    session.commit()

    response = client.get(
        "/api/traces/trace_123",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["trace_id"] == "trace_123"
    assert data["tool"] == "calculator"
    assert data["inputs"] == {"a": 1, "b": 2}
    assert data["output"] == {"result": 3}


def test_get_nonexistent_trace(client: TestClient, auth_token: str):
    """Test getting nonexistent trace returns 404."""
    response = client.get(
        "/api/traces/nonexistent",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert response.status_code == 404
