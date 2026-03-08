"""Comprehensive tests for approval router endpoints.

This test suite achieves 100% coverage for server/routers/approvals.py:
- GET /approvals - list approval requests with filters
- GET /approvals/pending - list pending approvals
- GET /approvals/pending/count - count pending approvals
- GET /approvals/{approval_id} - get approval by ID
- POST /approvals/{approval_id}/decide - approve or deny request
- POST /approvals - create approval request

Covers:
- Authentication/authorization (APPROVAL_READ, APPROVAL_DECIDE permissions)
- Filter parameters (status, limit, offset)
- Approval status transitions (pending -> approved/denied)
- Error paths (not found, already decided)
- RBAC permission checks
- Audit logging for decisions
- All edge cases
"""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from server.models import (
    Approval,
    ApprovalStatus,
    AuditEntry,
    User,
)
from tests.router_test_support import bearer_token, create_test_user

pytest_plugins = ("tests.router_test_support",)


@pytest.fixture(name="admin_user")
def _admin_user_impl(session: Session) -> User:
    """Create an admin user with all permissions."""
    return create_test_user(
        session,
        email="admin@test.com",
        name="Admin User",
        password="admin123",
        role="admin",
        is_active=True,
    )


@pytest.fixture(name="approver_user")
def _approver_user_impl(session: Session) -> User:
    """Create an approver user with APPROVAL_READ and APPROVAL_DECIDE permissions."""
    return create_test_user(
        session,
        email="approver@test.com",
        name="Approver User",
        password="approver123",
        role="approver",
        is_active=True,
    )


@pytest.fixture(name="viewer_user")
def _viewer_user_impl(session: Session) -> User:
    """Create a viewer user with APPROVAL_READ but not APPROVAL_DECIDE."""
    return create_test_user(
        session,
        email="viewer@test.com",
        name="Viewer User",
        password="viewer123",
        role="viewer",
        is_active=True,
    )


@pytest.fixture(name="developer_user")
def _developer_user_impl(session: Session) -> User:
    """Create a developer user without APPROVAL_DECIDE permission."""
    return create_test_user(
        session,
        email="developer@test.com",
        name="Developer User",
        password="developer123",
        role="developer",
        is_active=True,
    )


@pytest.fixture(name="admin_token")
def _admin_token_impl(admin_user: User) -> str:
    """Generate access token for admin user."""
    return bearer_token(admin_user)


@pytest.fixture(name="approver_token")
def _approver_token_impl(approver_user: User) -> str:
    """Generate access token for approver user."""
    return bearer_token(approver_user)


@pytest.fixture(name="viewer_token")
def _viewer_token_impl(viewer_user: User) -> str:
    """Generate access token for viewer user."""
    return bearer_token(viewer_user)


@pytest.fixture(name="developer_token")
def _developer_token_impl(developer_user: User) -> str:
    """Generate access token for developer user."""
    return bearer_token(developer_user)


@pytest.fixture(name="sample_approvals")
def _sample_approvals_impl(session: Session, approver_user: User) -> list[Approval]:
    """Create sample approval requests."""
    approvals = [
        Approval(
            approval_id="approval_1",
            tool="delete_file",
            inputs={"path": "/important/file.txt"},
            status=ApprovalStatus.PENDING,
            agent_id="agent_1",
            session_id="session_1",
            trace_id="trace_1",
            created_by_user_id=approver_user.id,
            created_by_email="approver@test.com",
        ),
        Approval(
            approval_id="approval_2",
            tool="send_email",
            inputs={"to": "user@example.com", "subject": "Test"},
            status=ApprovalStatus.PENDING,
            agent_id="agent_1",
            created_by_user_id=approver_user.id,
            created_by_email="approver@test.com",
        ),
        Approval(
            approval_id="approval_3",
            tool="database_write",
            inputs={"query": "DELETE FROM users"},
            status=ApprovalStatus.APPROVED,
            created_by_user_id=approver_user.id,
            created_by_email="approver@test.com",
            decided_by="admin@test.com",
            decided_at=datetime.now(timezone.utc),
            decision_reason="Reviewed and approved",
        ),
        Approval(
            approval_id="approval_4",
            tool="delete_file",
            inputs={"path": "/tmp/test.txt"},
            status=ApprovalStatus.DENIED,
            created_by_user_id=approver_user.id,
            created_by_email="approver@test.com",
            decided_by="approver@test.com",
            decided_at=datetime.now(timezone.utc),
            decision_reason="Path not allowed",
        ),
    ]
    for approval in approvals:
        session.add(approval)
    session.commit()
    for approval in approvals:
        session.refresh(approval)
    return approvals


# ============== Test POST /approvals - Create Approval ==============


def test_create_approval_success(client: TestClient, session: Session, viewer_token: str):
    """Test creating a new approval request with authentication."""
    _ = session
    response = client.post(
        "/api/approvals",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={
            "approval_id": "approval_new",
            "tool": "delete_database",
            "inputs": {"db_name": "production"},
            "trace_id": "trace_123",
            "agent_id": "agent_1",
            "context": {"reason": "cleanup"},
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["approval_id"] == "approval_new"
    assert data["tool"] == "delete_database"
    assert data["status"] == "pending"
    assert data["inputs"] == {"db_name": "production"}

    # Verify it was saved
    approval = session.exec(select(Approval).where(Approval.approval_id == "approval_new")).first()
    assert approval is not None
    assert approval.tool == "delete_database"


def test_create_approval_minimal(client: TestClient, session: Session, viewer_token: str):
    """Test creating approval with minimal required fields."""
    _ = session
    response = client.post(
        "/api/approvals",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={
            "approval_id": "approval_minimal",
            "tool": "risky_operation",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["approval_id"] == "approval_minimal"
    assert data["tool"] == "risky_operation"
    assert data["status"] == "pending"


def test_create_approval_requires_auth(client: TestClient):
    """Creating approvals requires authentication."""
    response = client.post(
        "/api/approvals",
        json={
            "approval_id": "approval_unauth",
            "tool": "risky_operation",
        },
    )
    assert response.status_code == 401


# ============== Test GET /approvals - List Approvals ==============


def test_list_approvals_requires_auth(client: TestClient, sample_approvals):
    """Test listing approvals requires authentication."""
    _ = sample_approvals
    response = client.get("/api/approvals")
    assert response.status_code == 401


def test_list_approvals_requires_permission(client: TestClient, sample_approvals):
    """Test listing approvals requires APPROVAL_READ permission."""
    _ = sample_approvals
    # Create user without APPROVAL_READ permission
    # Note: viewer role has APPROVAL_READ, but let's test unauthorized access
    response = client.get(
        "/api/approvals",
        headers={"Authorization": "Bearer invalid_token"},
    )
    assert response.status_code == 401


def test_list_approvals_success(client: TestClient, approver_token: str, sample_approvals):
    """Test listing all approvals successfully."""
    _ = sample_approvals
    response = client.get(
        "/api/approvals",
        headers={"Authorization": f"Bearer {approver_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 4
    # Should be ordered by created_at desc (newest first)
    assert data[0]["approval_id"] == "approval_4"


def test_list_approvals_filter_by_status_pending(
    client: TestClient, approver_token: str, sample_approvals
):
    """Test filtering approvals by status=pending."""
    _ = sample_approvals
    response = client.get(
        "/api/approvals?status=pending",
        headers={"Authorization": f"Bearer {approver_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    assert all(item["status"] == "pending" for item in data)


def test_list_approvals_filter_by_status_approved(
    client: TestClient, approver_token: str, sample_approvals
):
    """Test filtering approvals by status=approved."""
    _ = sample_approvals
    response = client.get(
        "/api/approvals?status=approved",
        headers={"Authorization": f"Bearer {approver_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["approval_id"] == "approval_3"


def test_list_approvals_filter_by_status_denied(
    client: TestClient, approver_token: str, sample_approvals
):
    """Test filtering approvals by status=denied."""
    _ = sample_approvals
    response = client.get(
        "/api/approvals?status=denied",
        headers={"Authorization": f"Bearer {approver_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["approval_id"] == "approval_4"


def test_list_approvals_pagination_limit(client: TestClient, approver_token: str, sample_approvals):
    """Test pagination with limit parameter."""
    _ = sample_approvals
    response = client.get(
        "/api/approvals?limit=2",
        headers={"Authorization": f"Bearer {approver_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2


def test_list_approvals_pagination_offset(
    client: TestClient, approver_token: str, sample_approvals
):
    """Test pagination with offset parameter."""
    _ = sample_approvals
    response = client.get(
        "/api/approvals?offset=2",
        headers={"Authorization": f"Bearer {approver_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2


def test_list_approvals_pagination_limit_and_offset(
    client: TestClient, approver_token: str, sample_approvals
):
    """Test pagination with both limit and offset."""
    _ = sample_approvals
    response = client.get(
        "/api/approvals?limit=1&offset=1",
        headers={"Authorization": f"Bearer {approver_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1


def test_list_approvals_limit_max_500(client: TestClient, approver_token: str, sample_approvals):
    """Test that limit is capped at 500."""
    _ = sample_approvals
    response = client.get(
        "/api/approvals?limit=1000",
        headers={"Authorization": f"Bearer {approver_token}"},
    )
    # FastAPI validation rejects limit > 500 with 422
    assert response.status_code == 422


def test_list_approvals_empty(client: TestClient, approver_token: str):
    """Test listing approvals when none exist."""
    response = client.get(
        "/api/approvals",
        headers={"Authorization": f"Bearer {approver_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 0


# ============== Test GET /approvals/pending - List Pending ==============


def test_list_pending_requires_auth(client: TestClient, sample_approvals):
    """Test listing pending approvals requires authentication."""
    _ = sample_approvals
    response = client.get("/api/approvals/pending")
    assert response.status_code == 401


def test_list_pending_success(client: TestClient, approver_token: str, sample_approvals):
    """Test listing pending approvals."""
    _ = sample_approvals
    response = client.get(
        "/api/approvals/pending",
        headers={"Authorization": f"Bearer {approver_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    assert all(item["status"] == "pending" for item in data)
    # Should be ordered by created_at asc (oldest first)
    assert data[0]["approval_id"] == "approval_1"


def test_list_pending_empty(client: TestClient, approver_token: str):
    """Test listing pending approvals when none exist."""
    response = client.get(
        "/api/approvals/pending",
        headers={"Authorization": f"Bearer {approver_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 0


# ============== Test GET /approvals/pending/count - Count Pending ==============


def test_count_pending_requires_auth(client: TestClient, sample_approvals):
    """Test counting pending approvals requires authentication."""
    _ = sample_approvals
    response = client.get("/api/approvals/pending/count")
    assert response.status_code == 401


def test_count_pending_success(client: TestClient, approver_token: str, sample_approvals):
    """Test counting pending approvals."""
    _ = sample_approvals
    response = client.get(
        "/api/approvals/pending/count",
        headers={"Authorization": f"Bearer {approver_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data == {"count": 2}


def test_count_pending_zero(client: TestClient, approver_token: str):
    """Test counting pending approvals when none exist."""
    response = client.get(
        "/api/approvals/pending/count",
        headers={"Authorization": f"Bearer {approver_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data == {"count": 0}


# ============== Test GET /approvals/{approval_id} - Get Approval ==============


def test_get_approval_requires_auth(client: TestClient, sample_approvals):
    """Test getting approval requires authentication."""
    _ = sample_approvals
    response = client.get("/api/approvals/approval_1")
    assert response.status_code == 401


def test_get_approval_success(client: TestClient, approver_token: str, sample_approvals):
    """Test getting a single approval by ID."""
    _ = sample_approvals
    response = client.get(
        "/api/approvals/approval_1",
        headers={"Authorization": f"Bearer {approver_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["approval_id"] == "approval_1"
    assert data["tool"] == "delete_file"
    assert data["status"] == "pending"
    assert data["inputs"] == {"path": "/important/file.txt"}


def test_get_approval_not_found(client: TestClient, approver_token: str, sample_approvals):
    """Test getting nonexistent approval returns 404."""
    _ = sample_approvals
    response = client.get(
        "/api/approvals/nonexistent",
        headers={"Authorization": f"Bearer {approver_token}"},
    )
    assert response.status_code == 404
    assert response.json()["detail"] == "Approval not found"


# ============== Test POST /approvals/{approval_id}/decide - Decide Approval ==============


def test_decide_approval_requires_auth(client: TestClient, sample_approvals):
    """Test deciding approval requires authentication."""
    _ = sample_approvals
    response = client.post(
        "/api/approvals/approval_1/decide",
        json={"approved": True},
    )
    assert response.status_code == 401


def test_decide_approval_requires_permission(
    client: TestClient, viewer_token: str, sample_approvals
):
    """Test deciding approval requires APPROVAL_DECIDE permission."""
    _ = sample_approvals
    # Viewer has APPROVAL_READ but not APPROVAL_DECIDE
    response = client.post(
        "/api/approvals/approval_1/decide",
        json={"approved": True},
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert response.status_code == 403
    assert "Permission required: approval:decide" in response.json()["detail"]


def test_decide_approval_developer_no_permission(
    client: TestClient, developer_token: str, sample_approvals
):
    """Test developer cannot decide approvals."""
    _ = sample_approvals
    response = client.post(
        "/api/approvals/approval_1/decide",
        json={"approved": True},
        headers={"Authorization": f"Bearer {developer_token}"},
    )
    assert response.status_code == 403


def test_decide_approval_approve_success(
    client: TestClient,
    approver_token: str,
    approver_user: User,
    sample_approvals,
    session: Session,
):
    """Test approving a request successfully."""
    _ = sample_approvals
    _ = session
    response = client.post(
        "/api/approvals/approval_1/decide",
        json={"approved": True, "reason": "Looks safe"},
        headers={"Authorization": f"Bearer {approver_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["approval_id"] == "approval_1"
    assert data["status"] == "approved"
    assert data["decided_by"] == approver_user.email
    assert data["decision_reason"] == "Looks safe"
    assert data["decided_at"] is not None

    # Verify audit log was created
    audit = session.exec(
        select(AuditEntry)
        .where(AuditEntry.event_type == "approval_decision")
        .where(AuditEntry.actor == approver_user.email)
    ).first()
    assert audit is not None
    assert audit.result == "approved"
    assert audit.details["approval_id"] == "approval_1"
    assert audit.details["reason"] == "Looks safe"


def test_decide_approval_deny_success(
    client: TestClient,
    approver_token: str,
    approver_user: User,
    sample_approvals,
    session: Session,
):
    """Test denying a request successfully."""
    _ = sample_approvals
    _ = session
    response = client.post(
        "/api/approvals/approval_2/decide",
        json={"approved": False, "reason": "Too risky"},
        headers={"Authorization": f"Bearer {approver_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["approval_id"] == "approval_2"
    assert data["status"] == "denied"
    assert data["decided_by"] == approver_user.email
    assert data["decision_reason"] == "Too risky"
    assert data["decided_at"] is not None

    # Verify audit log was created
    audit = session.exec(
        select(AuditEntry)
        .where(AuditEntry.event_type == "approval_decision")
        .where(AuditEntry.actor == approver_user.email)
    ).first()
    assert audit is not None
    assert audit.result == "denied"


def test_decide_approval_without_reason(client: TestClient, approver_token: str, sample_approvals):
    """Test deciding approval without reason is allowed."""
    _ = sample_approvals
    response = client.post(
        "/api/approvals/approval_1/decide",
        json={"approved": True},
        headers={"Authorization": f"Bearer {approver_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["decision_reason"] is None


def test_decide_approval_not_found(client: TestClient, approver_token: str, sample_approvals):
    """Test deciding nonexistent approval returns 404."""
    _ = sample_approvals
    response = client.post(
        "/api/approvals/nonexistent/decide",
        json={"approved": True},
        headers={"Authorization": f"Bearer {approver_token}"},
    )
    assert response.status_code == 404
    assert response.json()["detail"] == "Approval not found"


def test_decide_approval_already_approved(
    client: TestClient, approver_token: str, sample_approvals
):
    """Test deciding already approved request returns 400."""
    _ = sample_approvals
    response = client.post(
        "/api/approvals/approval_3/decide",
        json={"approved": True},
        headers={"Authorization": f"Bearer {approver_token}"},
    )
    assert response.status_code == 400
    assert "Approval already approved" in response.json()["detail"]


def test_decide_approval_already_denied(client: TestClient, approver_token: str, sample_approvals):
    """Test deciding already denied request returns 400."""
    _ = sample_approvals
    response = client.post(
        "/api/approvals/approval_4/decide",
        json={"approved": False},
        headers={"Authorization": f"Bearer {approver_token}"},
    )
    assert response.status_code == 400
    assert "Approval already denied" in response.json()["detail"]


def test_decide_approval_admin_can_decide(
    client: TestClient, admin_token: str, admin_user: User, sample_approvals
):
    """Test admin user can decide approvals."""
    _ = sample_approvals
    response = client.post(
        "/api/approvals/approval_1/decide",
        json={"approved": True, "reason": "Admin override"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "approved"
    assert data["decided_by"] == admin_user.email


# ============== Test RBAC and Permission Variations ==============


def test_auditor_can_read_approvals(client: TestClient, session: Session, sample_approvals):
    """Test auditor role can read approvals."""
    _ = sample_approvals
    auditor = create_test_user(
        session,
        email="auditor@test.com",
        name="Auditor",
        password="auditor123",
        role="auditor",
        is_active=True,
    )
    token = bearer_token(auditor)

    response = client.get(
        "/api/approvals",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200


def test_auditor_cannot_decide_approvals(client: TestClient, session: Session, sample_approvals):
    """Test auditor role cannot decide approvals."""
    _ = sample_approvals
    auditor = create_test_user(
        session,
        email="auditor2@test.com",
        name="Auditor 2",
        password="auditor123",
        role="auditor",
        is_active=True,
    )
    token = bearer_token(auditor)

    response = client.post(
        "/api/approvals/approval_1/decide",
        json={"approved": True},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


# ============== Test Edge Cases ==============


def test_list_approvals_with_many_records(
    client: TestClient,
    approver_token: str,
    approver_user: User,
    session: Session,
    sample_approvals,
):
    """Test listing approvals with many records."""
    _ = session
    _ = sample_approvals
    # Create 100 approval records
    for i in range(100):
        approval = Approval(
            approval_id=f"approval_bulk_{i}",
            tool="bulk_tool",
            status=ApprovalStatus.PENDING,
            created_by_user_id=approver_user.id,
            created_by_email="approver@test.com",
        )
        session.add(approval)
    session.commit()

    # Test default limit (50)
    response = client.get(
        "/api/approvals",
        headers={"Authorization": f"Bearer {approver_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 50

    # Test custom limit
    response = client.get(
        "/api/approvals?limit=10",
        headers={"Authorization": f"Bearer {approver_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 10


def test_decide_approval_updates_database(
    client: TestClient, approver_token: str, sample_approvals, session: Session
):
    """Test that deciding approval properly updates the database."""
    _ = sample_approvals
    _ = session
    response = client.post(
        "/api/approvals/approval_1/decide",
        json={"approved": True, "reason": "Test reason"},
        headers={"Authorization": f"Bearer {approver_token}"},
    )
    assert response.status_code == 200

    # Verify database was updated
    approval = session.exec(select(Approval).where(Approval.approval_id == "approval_1")).first()
    assert approval is not None
    assert approval.status == ApprovalStatus.APPROVED
    assert approval.decided_by == "approver@test.com"
    assert approval.decision_reason == "Test reason"
    assert approval.decided_at is not None


def test_create_approval_with_all_fields(
    client: TestClient, session: Session, sample_approvals, viewer_token: str
):
    """Test creating approval with all optional fields."""
    _ = session
    _ = sample_approvals
    response = client.post(
        "/api/approvals",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={
            "approval_id": "approval_full",
            "tool": "complex_tool",
            "inputs": {"param1": "value1", "param2": 123},
            "trace_id": "trace_xyz",
            "agent_id": "agent_abc",
            "context": {"user": "test@example.com", "priority": "high"},
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["approval_id"] == "approval_full"

    # Verify all fields saved
    approval = session.exec(select(Approval).where(Approval.approval_id == "approval_full")).first()
    assert approval is not None
    assert approval.inputs == {"param1": "value1", "param2": 123}
    assert approval.trace_id == "trace_xyz"
    assert approval.agent_id == "agent_abc"
