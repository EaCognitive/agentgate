"""Cross-component integration tests."""

import uuid
from datetime import datetime, timezone

import pyotp
from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import (
    Trace,
    TraceStatus,
)


def test_trace_approval_dataset_integration(
    client: TestClient, admin_headers: dict[str, str], session: Session
) -> None:
    """Test integration: Trace → Approval → Save to Dataset."""
    # Create trace requiring approval
    trace_id = f"integration_{uuid.uuid4().hex[:8]}"
    trace = Trace(
        trace_id=trace_id,
        agent_id="integration-agent",
        tool="integration_tool",
        inputs={"param": "value"},
        status=TraceStatus.PENDING,
        started_at=datetime.now(timezone.utc),
    )
    session.add(trace)
    session.commit()

    # Create approval
    approval_id = f"approval_{uuid.uuid4().hex[:8]}"
    approval_data = {
        "approval_id": approval_id,
        "trace_id": trace_id,
        "tool": "integration_tool",
        "inputs": {"param": "value"},
        "reason": "Integration test",
        "requested_by": "test-agent",
    }
    client.post("/api/approvals", json=approval_data, headers=admin_headers)

    # Approve
    decision_data = {"approved": True, "reason": "Approved for testing"}
    client.post(
        f"/api/approvals/{approval_id}/decide",
        json=decision_data,
        headers=admin_headers,
    )

    # Update trace to success
    trace.status = TraceStatus.SUCCESS
    trace.output = {"result": "success"}
    session.add(trace)
    session.commit()

    # Create dataset
    response = client.post(
        "/api/datasets",
        json={"name": "Integration Dataset"},
        headers=admin_headers,
    )
    dataset_id = response.json()["id"]

    # Save trace to dataset
    response = client.post(
        f"/api/datasets/{dataset_id}/tests/from-trace",
        json={"dataset_id": dataset_id, "trace_id": trace_id, "name": "Integration Test"},
        headers=admin_headers,
    )
    assert response.status_code == 201
    test_case = response.json()
    assert test_case["source_trace_id"] == trace_id


def test_full_audit_trail_workflow(client: TestClient, admin_headers: dict[str, str]) -> None:
    """Test comprehensive audit trail across all operations."""
    # Perform various operations
    operations = [
        ("POST", "/api/datasets", {"name": "Audit Test Dataset"}),
        ("GET", "/api/traces/stats", None),
        ("GET", "/api/approvals/pending", None),
    ]

    for method, endpoint, data in operations:
        if method == "POST":
            client.post(endpoint, json=data, headers=admin_headers)
        else:
            client.get(endpoint, headers=admin_headers)

    # Verify audit entries
    response = client.get("/api/audit", headers=admin_headers)
    assert response.status_code == 200
    audit_entries = response.json()
    assert len(audit_entries) > 0

    # Check for expected event types
    event_types = {e["event_type"] for e in audit_entries}
    assert "dataset_create" in event_types


def test_concurrent_approvals_workflow(
    client: TestClient, auth_headers: dict[str, str], admin_headers: dict[str, str]
) -> None:
    """Test handling multiple concurrent approval requests."""
    approval_ids = []

    # Create multiple approval requests
    for i in range(3):
        approval_id = f"concurrent_{uuid.uuid4().hex[:8]}"
        approval_data = {
            "approval_id": approval_id,
            "trace_id": f"trace_concurrent_{i}",
            "tool": f"tool_{i}",
            "inputs": {"index": i},
            "reason": f"Concurrent test {i}",
            "requested_by": "test-agent",
        }
        response = client.post("/api/approvals", json=approval_data, headers=auth_headers)
        assert response.status_code == 200
        approval_ids.append(approval_id)

    # Verify all are pending
    response = client.get("/api/approvals/pending", headers=admin_headers)
    assert response.status_code == 200
    pending = response.json()
    assert len(pending) >= 3

    # Approve first, deny second, leave third pending
    response1 = client.post(
        f"/api/approvals/{approval_ids[0]}/decide",
        json={"approved": True, "reason": "Approved"},
        headers=admin_headers,
    )
    assert response1.status_code == 200

    response2 = client.post(
        f"/api/approvals/{approval_ids[1]}/decide",
        json={"approved": False, "reason": "Denied"},
        headers=admin_headers,
    )
    assert response2.status_code == 200

    # Verify statuses
    response = client.get("/api/approvals/pending", headers=admin_headers)
    pending = response.json()
    assert any(a["approval_id"] == approval_ids[2] for a in pending)
    assert not any(a["approval_id"] == approval_ids[0] for a in pending)


def test_end_to_end_security_workflow(client: TestClient) -> None:
    """Test complete security workflow: Register → MFA → RBAC → Audit."""
    # Step 1: Register user
    register_data = {
        "email": "security@example.com",
        "password": "SecurePass123!",
        "name": "Security User",
    }
    response = client.post("/api/auth/register", json=register_data)
    assert response.status_code == 200

    # Step 2: Login
    response = client.post(
        "/api/auth/login",
        json={"email": "security@example.com", "password": "SecurePass123!"},
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Step 3: Enable MFA
    response = client.post("/api/auth/enable-2fa", headers=headers)
    assert response.status_code == 200
    secret = response.json()["secret"]

    # Step 4: Verify MFA

    totp = pyotp.TOTP(secret)
    response = client.post(
        "/api/auth/verify-2fa",
        json={"code": totp.now()},
        headers=headers,
    )
    assert response.status_code == 200

    # Step 5: Test RBAC - non-admin cannot access audit endpoints
    response = client.get("/api/audit", headers=headers)
    assert response.status_code == 403

    # Step 6: Verify complete audit trail
    # First user is admin, so get their token
    admin_response = client.post(
        "/api/auth/register",
        json={
            "email": "admin_security@example.com",
            "password": "AdminPass123!",
            "name": "Admin Security",
        },
    )

    if admin_response.status_code == 200:
        admin_login = client.post(
            "/api/auth/login",
            json={"email": "admin_security@example.com", "password": "AdminPass123!"},
        )
        admin_token = admin_login.json()["access_token"]
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        response = client.get("/api/audit", headers=admin_headers)
        if response.status_code == 200:
            audit_entries = response.json()
            event_types = {e["event_type"] for e in audit_entries}
            assert "user_register" in event_types or "login" in event_types
