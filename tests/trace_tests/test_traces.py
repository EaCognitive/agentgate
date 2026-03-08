"""Comprehensive tests for the traces router endpoints.

Tests cover:
- Trace creation (POST /api/traces)
- Listing traces with filters (GET /api/traces)
- Getting trace by ID (GET /api/traces/{id})
- Statistics endpoint (GET /api/traces/stats)
- Timeline endpoint (GET /api/traces/timeline)
- Tool stats endpoint (GET /api/traces/tools)
- Viewable traces endpoint (GET /api/traces/viewable)
- Authentication and authorization controls
"""

from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import Trace, TraceStatus


def test_create_trace_success(
    client: TestClient,
    admin_token: str,
) -> None:
    """Test creating a trace with valid payload returns 200 and trace_id."""
    response = client.post(
        "/api/traces",
        json={
            "trace_id": "trace_test_create",
            "tool": "bash",
            "inputs": {"command": "echo hello"},
            "output": {"result": "hello"},
            "status": "success",
            "cost": 0.01,
            "agent_id": "agent-alpha",
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["trace_id"] == "trace_test_create"
    assert data["tool"] == "bash"
    assert data["status"] == "success"
    assert data["cost"] == 0.01


def test_list_traces(
    client: TestClient,
    admin_token: str,
    test_trace: Trace,
) -> None:
    """Test listing traces returns 200 and list of traces."""
    _ = test_trace
    response = client.get(
        "/api/traces",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    trace_ids = [t["trace_id"] for t in data]
    assert "test_trace" in trace_ids


def test_list_traces_with_status_filter(
    client: TestClient,
    admin_token: str,
    session: Session,
) -> None:
    """Test listing traces filtered by status."""
    success_trace = Trace(
        trace_id="success_trace",
        tool="test_tool",
        status=TraceStatus.SUCCESS,
        inputs={},
        output={},
        started_at=datetime.now(timezone.utc),
    )
    failed_trace = Trace(
        trace_id="failed_trace",
        tool="test_tool",
        status=TraceStatus.FAILED,
        inputs={},
        output={},
        started_at=datetime.now(timezone.utc),
    )
    session.add(success_trace)
    session.add(failed_trace)
    session.commit()

    response = client.get(
        "/api/traces?status=success",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert all(t["status"] == "success" for t in data)


def test_list_traces_with_tool_filter(
    client: TestClient,
    admin_token: str,
    session: Session,
) -> None:
    """Test listing traces filtered by tool."""
    bash_trace = Trace(
        trace_id="bash_trace",
        tool="bash",
        status=TraceStatus.SUCCESS,
        inputs={},
        output={},
        started_at=datetime.now(timezone.utc),
    )
    python_trace = Trace(
        trace_id="python_trace",
        tool="python",
        status=TraceStatus.SUCCESS,
        inputs={},
        output={},
        started_at=datetime.now(timezone.utc),
    )
    session.add(bash_trace)
    session.add(python_trace)
    session.commit()

    response = client.get(
        "/api/traces?tool=bash",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert all(t["tool"] == "bash" for t in data)


def test_list_traces_with_agent_id_filter(
    client: TestClient,
    admin_token: str,
    session: Session,
) -> None:
    """Test listing traces filtered by agent_id."""
    agent1_trace = Trace(
        trace_id="agent1_trace",
        tool="test",
        agent_id="agent-1",
        status=TraceStatus.SUCCESS,
        inputs={},
        output={},
        started_at=datetime.now(timezone.utc),
    )
    agent2_trace = Trace(
        trace_id="agent2_trace",
        tool="test",
        agent_id="agent-2",
        status=TraceStatus.SUCCESS,
        inputs={},
        output={},
        started_at=datetime.now(timezone.utc),
    )
    session.add(agent1_trace)
    session.add(agent2_trace)
    session.commit()

    response = client.get(
        "/api/traces?agent_id=agent-1",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert all(t["agent_id"] == "agent-1" for t in data)


def test_list_traces_with_limit_and_offset(
    client: TestClient,
    admin_token: str,
    session: Session,
) -> None:
    """Test listing traces with limit and offset pagination."""
    for i in range(5):
        trace = Trace(
            trace_id=f"trace_{i}",
            tool="test",
            status=TraceStatus.SUCCESS,
            inputs={},
            output={},
            started_at=datetime.now(timezone.utc),
        )
        session.add(trace)
    session.commit()

    response = client.get(
        "/api/traces?limit=2&offset=1",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2


def test_get_trace_by_id_found(
    client: TestClient,
    admin_token: str,
    test_trace: Trace,
) -> None:
    """Test getting a trace by ID returns 200 when found."""
    _ = test_trace
    response = client.get(
        "/api/traces/test_trace",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["trace_id"] == "test_trace"
    assert data["tool"] == "test_tool"


def test_get_trace_by_id_not_found(
    client: TestClient,
    admin_token: str,
) -> None:
    """Test getting a non-existent trace returns 404."""
    response = client.get(
        "/api/traces/nonexistent_trace",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 404
    data = response.json()
    assert "not found" in data["detail"].lower()


def test_stats_endpoint(
    client: TestClient,
    admin_token: str,
    session: Session,
) -> None:
    """Test stats endpoint returns expected structure."""
    now = datetime.now(timezone.utc)
    for status in [
        TraceStatus.SUCCESS,
        TraceStatus.SUCCESS,
        TraceStatus.FAILED,
    ]:
        trace = Trace(
            trace_id=f"stats_trace_{status.value}_{id(status)}",
            tool="test",
            status=status,
            inputs={},
            output={},
            started_at=now,
        )
        session.add(trace)
    session.commit()

    response = client.get(
        "/api/traces/stats",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "success" in data
    assert "failed" in data
    assert "blocked" in data
    assert "pending" in data
    assert "success_rate" in data
    assert "period_hours" in data
    assert data["total"] >= 3


def test_timeline_endpoint(
    client: TestClient,
    admin_token: str,
    session: Session,
) -> None:
    """Test timeline endpoint returns time-bucketed list."""
    now = datetime.now(timezone.utc)
    trace = Trace(
        trace_id="timeline_trace",
        tool="test",
        status=TraceStatus.SUCCESS,
        inputs={},
        output={},
        started_at=now,
    )
    session.add(trace)
    session.commit()

    response = client.get(
        "/api/traces/timeline",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    if data:
        assert "time" in data[0]
        assert "success" in data[0]
        assert "failed" in data[0]
        assert "blocked" in data[0]


def test_tools_endpoint(
    client: TestClient,
    admin_token: str,
    session: Session,
) -> None:
    """Test tools endpoint returns per-tool statistics."""
    now = datetime.now(timezone.utc)
    bash_trace = Trace(
        trace_id="tools_bash_trace",
        tool="bash",
        status=TraceStatus.SUCCESS,
        inputs={},
        output={},
        duration_ms=100.0,
        cost=0.01,
        started_at=now,
    )
    python_trace = Trace(
        trace_id="tools_python_trace",
        tool="python",
        status=TraceStatus.FAILED,
        inputs={},
        output={},
        duration_ms=200.0,
        cost=0.02,
        started_at=now,
    )
    session.add(bash_trace)
    session.add(python_trace)
    session.commit()

    response = client.get(
        "/api/traces/tools",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    if data:
        tool_names = [t["tool"] for t in data]
        assert "bash" in tool_names or "python" in tool_names


def test_viewable_endpoint(
    client: TestClient,
    admin_token: str,
    test_trace: Trace,
) -> None:
    """Test viewable traces endpoint returns list."""
    _ = test_trace
    response = client.get(
        "/api/traces/viewable",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


def test_unauthenticated_list_traces(
    client: TestClient,
) -> None:
    """Test listing traces without token returns 401."""
    response = client.get("/api/traces")
    assert response.status_code == 401


def test_unauthenticated_get_trace(
    client: TestClient,
    test_trace: Trace,
) -> None:
    """Test getting trace by ID without token returns 401."""
    _ = test_trace
    response = client.get("/api/traces/test_trace")
    assert response.status_code == 401


def test_unauthenticated_create_trace(
    client: TestClient,
) -> None:
    """Test creating trace without token returns 401."""
    response = client.post(
        "/api/traces",
        json={
            "trace_id": "unauthorized_trace",
            "tool": "bash",
            "inputs": {},
            "output": {},
            "status": "success",
        },
    )
    assert response.status_code == 401


def test_viewer_cannot_create_trace(
    client: TestClient,
    viewer_token: str,
) -> None:
    """Test viewer role cannot create traces (403)."""
    response = client.post(
        "/api/traces",
        json={
            "trace_id": "viewer_trace",
            "tool": "bash",
            "inputs": {},
            "output": {},
            "status": "success",
        },
        headers={"Authorization": f"Bearer {viewer_token}"},
    )

    assert response.status_code == 403
    data = response.json()
    assert "cannot create" in data["detail"].lower()


def test_viewer_can_list_traces(
    client: TestClient,
    viewer_token: str,
    test_trace: Trace,
) -> None:
    """Test viewer role can list traces (200)."""
    _ = test_trace
    response = client.get(
        "/api/traces",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


def test_viewer_can_get_trace(
    client: TestClient,
    viewer_token: str,
    viewer_user,
    session: Session,
) -> None:
    """Test viewer role can get trace by ID when they own it (200)."""
    viewer_trace = Trace(
        trace_id="viewer_owned_trace",
        tool="test_tool",
        status=TraceStatus.SUCCESS,
        inputs={},
        output={},
        created_by=viewer_user.id,
        started_at=datetime.now(timezone.utc),
    )
    session.add(viewer_trace)
    session.commit()

    response = client.get(
        "/api/traces/viewer_owned_trace",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["trace_id"] == "viewer_owned_trace"


def test_viewer_can_access_stats(
    client: TestClient,
    viewer_token: str,
) -> None:
    """Test viewer role can access stats endpoint (200)."""
    response = client.get(
        "/api/traces/stats",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert "total" in data


def test_viewer_can_access_timeline(
    client: TestClient,
    viewer_token: str,
) -> None:
    """Test viewer role can access timeline endpoint (200)."""
    response = client.get(
        "/api/traces/timeline",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


def test_viewer_can_access_tools(
    client: TestClient,
    viewer_token: str,
) -> None:
    """Test viewer role can access tools endpoint (200)."""
    response = client.get(
        "/api/traces/tools",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
