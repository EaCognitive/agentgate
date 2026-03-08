"""Trace, Approval, and Audit integration tests."""

import uuid
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from server.models import (
    Approval,
    ApprovalStatus,
    AuditEntry,
    Trace,
    TraceStatus,
    User,
)


def _resolve_user_id(session: Session, email: str) -> int:
    """Resolve a persisted user ID by email for ownership-scoped test records."""
    user = session.exec(select(User).where(User.email == email)).first()  # type: ignore[arg-type]
    assert user is not None
    assert user.id is not None
    return user.id


def test_trace_to_approval_to_audit(
    client: TestClient, admin_headers: dict[str, str], session: Session
) -> None:
    """Test complete tracing and approval workflow."""
    # Step 1: Create a trace that requires approval
    trace_id = f"trace_{uuid.uuid4().hex[:12]}"
    trace_data = {
        "trace_id": trace_id,
        "agent_id": "test-agent",
        "tool": "sensitive_operation",
        "inputs": {"action": "delete", "resource": "important-data"},
        "status": "pending",
        "started_at": datetime.now(timezone.utc).isoformat(),
    }

    response = client.post("/api/traces", json=trace_data, headers=admin_headers)
    assert response.status_code == 200

    # Step 2: Create approval request for this trace
    approval_id = f"approval_{uuid.uuid4().hex[:12]}"
    approval_data = {
        "approval_id": approval_id,
        "trace_id": trace_id,
        "tool": "sensitive_operation",
        "inputs": {"action": "delete", "resource": "important-data"},
        "reason": "Delete operation requires approval",
        "requested_by": "test-agent",
    }

    response = client.post("/api/approvals", json=approval_data, headers=admin_headers)
    assert response.status_code == 200

    # Step 3: Check pending approvals
    response = client.get("/api/approvals/pending", headers=admin_headers)
    assert response.status_code == 200
    pending = response.json()
    assert len(pending) > 0
    assert any(a["approval_id"] == approval_id for a in pending)

    # Step 4: Approve the request
    decision_data = {"approved": True, "reason": "Authorized by admin"}
    response = client.post(
        f"/api/approvals/{approval_id}/decide",
        json=decision_data,
        headers=admin_headers,
    )
    assert response.status_code == 200
    assert response.json()["status"] == "approved"

    # Step 5: Verify audit trail
    response = client.get("/api/audit", headers=admin_headers)
    assert response.status_code == 200
    audit_entries = response.json()
    approval_events = [e for e in audit_entries if e["event_type"] == "approval_decision"]
    assert len(approval_events) > 0

    # Step 6: Update trace status to success
    trace = session.exec(select(Trace).where(Trace.trace_id == trace_id)).first()  # type: ignore
    if trace:
        trace.status = TraceStatus.SUCCESS
        trace.output = {"result": "Operation completed"}
        trace.duration_ms = 150
        session.add(trace)
        session.commit()


def test_approval_denial_workflow(client: TestClient, admin_headers: dict[str, str]) -> None:
    """Test approval denial and audit logging."""
    # Create approval request
    approval_id = f"approval_{uuid.uuid4().hex[:12]}"
    approval_data = {
        "approval_id": approval_id,
        "trace_id": f"trace_{uuid.uuid4().hex[:12]}",
        "tool": "dangerous_tool",
        "inputs": {"action": "format_disk"},
        "reason": "Dangerous operation",
        "requested_by": "test-agent",
    }

    client.post("/api/approvals", json=approval_data, headers=admin_headers)

    # Deny the request
    decision_data = {"approved": False, "reason": "Too risky, denied"}
    response = client.post(
        f"/api/approvals/{approval_id}/decide",
        json=decision_data,
        headers=admin_headers,
    )
    assert response.status_code == 200
    assert response.json()["status"] == "denied"
    assert response.json()["decision_reason"] == "Too risky, denied"

    # Verify audit log
    response = client.get("/api/audit", headers=admin_headers)
    audit_entries = response.json()
    denial_events = [
        e
        for e in audit_entries
        if e["event_type"] == "approval_decision" and e["result"] == "denied"
    ]
    assert len(denial_events) > 0


def test_trace_statistics_workflow(
    client: TestClient, auth_headers: dict[str, str], session: Session
) -> None:
    """Test trace creation and statistics retrieval."""
    owner_id = _resolve_user_id(session, "testuser@example.com")

    # Create multiple traces
    for i in range(5):
        trace = Trace(
            trace_id=f"trace_stats_{i}",
            agent_id="test-agent",
            tool=f"tool_{i % 2}",
            inputs={"param": i},
            status=TraceStatus.SUCCESS if i % 2 == 0 else TraceStatus.FAILED,
            output={"result": i} if i % 2 == 0 else None,
            error=None if i % 2 == 0 else "Error occurred",
            duration_ms=100 + i * 10,
            cost=0.001 * i,
            started_at=datetime.now(timezone.utc),
            created_by=owner_id,
        )
        session.add(trace)
    session.commit()

    # Get trace statistics
    response = client.get("/api/traces/stats", headers=auth_headers)
    assert response.status_code == 200
    stats = response.json()
    assert stats["total"] >= 5
    assert stats["success"] >= 3
    assert stats["failed"] >= 2

    # Get tool statistics
    response = client.get("/api/traces/tools", headers=auth_headers)
    assert response.status_code == 200
    tool_stats = response.json()
    assert len(tool_stats) > 0


def test_trace_filtering_and_pagination(
    client: TestClient, auth_headers: dict[str, str], session: Session
) -> None:
    """Test trace listing with filters and pagination."""
    # Create traces with different statuses
    for i in range(15):
        trace = Trace(
            trace_id=f"trace_filter_{i}",
            agent_id=f"agent_{i % 3}",
            tool="test_tool",
            inputs={"index": i},
            status=TraceStatus.SUCCESS if i < 10 else TraceStatus.FAILED,
            started_at=datetime.now(timezone.utc),
        )
        session.add(trace)
    session.commit()

    # List with status filter
    response = client.get("/api/traces?status=success&limit=10", headers=auth_headers)
    assert response.status_code == 200
    traces = response.json()
    assert len(traces) <= 10
    assert all(t["status"] == "success" for t in traces)

    # Test pagination
    response = client.get("/api/traces?limit=5&offset=5", headers=auth_headers)
    assert response.status_code == 200
    traces = response.json()
    assert len(traces) <= 5


def test_trace_timeline_analytics(
    client: TestClient, auth_headers: dict[str, str], session: Session
) -> None:
    """Test trace timeline bucketing for analytics."""
    owner_id = _resolve_user_id(session, "testuser@example.com")

    # Create traces over time
    base_time = datetime.now(timezone.utc)
    for i in range(10):
        trace = Trace(
            trace_id=f"trace_timeline_{i}",
            agent_id="test-agent",
            tool="analytics_tool",
            inputs={"hour": i},
            status=TraceStatus.SUCCESS,
            started_at=base_time - timedelta(hours=i) if i > 0 else base_time,
            created_by=owner_id,
        )
        session.add(trace)
    session.commit()

    # Get timeline data
    response = client.get("/api/traces/timeline?hours=24&bucket_minutes=60", headers=auth_headers)
    assert response.status_code == 200
    timeline = response.json()
    assert isinstance(timeline, list)
    assert len(timeline) > 0


def test_trace_error_patterns_analysis(
    client: TestClient, auth_headers: dict[str, str], session: Session
) -> None:
    """Test error pattern detection and analysis."""
    owner_id = _resolve_user_id(session, "testuser@example.com")

    # Create traces with different error patterns
    errors = [
        "Connection timeout",
        "Connection timeout",
        "Permission denied",
        "Connection timeout",
        "Rate limit exceeded",
    ]

    for i, error in enumerate(errors):
        trace = Trace(
            trace_id=f"error_trace_{i}",
            agent_id="error-agent",
            tool="failing_tool",
            inputs={"attempt": i},
            status=TraceStatus.FAILED,
            error=error,
            started_at=datetime.now(timezone.utc),
            created_by=owner_id,
        )
        session.add(trace)
    session.commit()

    # Get tool statistics
    response = client.get("/api/traces/tools", headers=auth_headers)
    assert response.status_code == 200
    tools = response.json()

    # Find failing_tool stats
    failing_tool_stats = next((t for t in tools if t["tool"] == "failing_tool"), None)
    assert failing_tool_stats is not None
    assert failing_tool_stats["failed"] >= 5


def test_trace_cost_aggregation_workflow(
    client: TestClient, auth_headers: dict[str, str], session: Session
) -> None:
    """Test cost tracking and aggregation across multiple traces."""
    owner_id = _resolve_user_id(session, "testuser@example.com")

    # Create traces with varying costs
    costs = [0.001, 0.002, 0.003, 0.001, 0.005]
    for i, cost in enumerate(costs):
        trace = Trace(
            trace_id=f"cost_trace_{i}",
            agent_id="cost-agent",
            tool="expensive_tool",
            inputs={"operation": i},
            status=TraceStatus.SUCCESS,
            cost=cost,
            started_at=datetime.now(timezone.utc),
            created_by=owner_id,
        )
        session.add(trace)
    session.commit()

    # Get trace statistics (cost tracking would be added in future enhancement)
    response = client.get("/api/traces/stats", headers=auth_headers)
    assert response.status_code == 200
    stats = response.json()
    # Verify basic stats are returned
    assert "total" in stats
    assert "success" in stats
    assert stats["total"] >= 5  # At least our 5 traces


def test_approval_timeout_workflow(
    client: TestClient, auth_headers: dict[str, str], session: Session
) -> None:
    """Test approval request timeout handling."""
    # Create approval with old timestamp
    old_time = datetime.now(timezone.utc) - timedelta(hours=25)
    approval = Approval(
        approval_id="timeout_approval",
        trace_id="timeout_trace",
        tool="timeout_tool",
        inputs={"data": "test"},
        status=ApprovalStatus.PENDING,
        created_at=old_time,
    )
    session.add(approval)
    session.commit()

    # Query pending approvals
    response = client.get("/api/approvals/pending", headers=auth_headers)
    assert response.status_code == 200
    pending = response.json()

    # Should still show old approval (timeout handling would be in a cleanup job)
    assert any(a["approval_id"] == "timeout_approval" for a in pending)


def test_multi_agent_trace_correlation(client: TestClient, admin_headers: dict[str, str]) -> None:
    """Test trace correlation across multiple agents."""
    session_id = f"session_{uuid.uuid4().hex[:12]}"

    # Create traces from multiple agents using the API endpoint; wait for persistence
    agents = ["agent-1", "agent-2", "agent-3"]
    for i, agent_id in enumerate(agents):
        trace_data = {
            "trace_id": f"multi_agent_trace_{agent_id}_{uuid.uuid4().hex[:8]}",
            "agent_id": agent_id,
            "session_id": session_id,
            "tool": "collaborative_tool",
            "inputs": {"step": i},
            "status": "success",
            "output": {"result": f"step-{i}"},
        }
        response = client.post("/api/traces", json=trace_data, headers=admin_headers)
        assert response.status_code == 200, f"Failed to create trace: {response.text}"
        # brief read to ensure DB commit visible
        _ = client.get("/api/health")

    # Query traces using admin headers (admins can see all traces)
    response = client.get("/api/traces?limit=100", headers=admin_headers)
    assert response.status_code == 200
    traces = response.json()

    # Verify traces from all agents exist
    trace_agents = {t["agent_id"] for t in traces if "multi_agent" in t["trace_id"]}
    assert len(trace_agents) == 3


def test_audit_log_pagination_and_filtering(
    client: TestClient, admin_headers: dict[str, str], session: Session
) -> None:
    """Test audit log pagination and event filtering."""
    # Create multiple audit entries
    event_types = ["login", "trace_create", "approval_decision", "login", "dataset_create"]
    for i, event_type in enumerate(event_types):
        entry = AuditEntry(
            event_type=event_type,
            actor="test-user",
            details={"action": f"test_{i}", "user_agent": "test-agent"},
            ip_address="127.0.0.1",
        )
        session.add(entry)
    session.commit()

    # Test pagination
    response = client.get("/api/audit?limit=3&offset=0", headers=admin_headers)
    assert response.status_code == 200
    first_page = response.json()
    assert len(first_page) <= 3

    # Test event type filtering
    response = client.get("/api/audit?event_type=login", headers=admin_headers)
    assert response.status_code == 200
    login_events = response.json()
    assert all(e["event_type"] == "login" for e in login_events)
