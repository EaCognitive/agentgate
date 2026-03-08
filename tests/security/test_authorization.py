"""Authorization tests: viewer role restrictions.

Tests verify:
- Viewer role cannot modify data
- Read-only access is enforced
- Admin-only endpoints are blocked for viewers

Sibling modules:
- test_authorization_escalation.py (privilege escalation)
- test_authorization_isolation.py (user data isolation)

Enterprise Engineering Protocols 2025
Zero trust security model
"""

from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import (
    Approval,
    ApprovalStatus,
    Dataset,
    User,
)

pytest_plugins = ("tests.security.authz_test_support",)


# =============================================================
# VIEWER ROLE RESTRICTIONS (16 tests)
# =============================================================


def test_viewer_cannot_create_traces(
    client: TestClient,
    viewer_token: str,
):
    """Viewer cannot create traces via API."""
    response = client.post(
        "/api/traces",
        headers={"Authorization": (f"Bearer {viewer_token}")},
        json={
            "trace_id": "test-trace-123",
            "tool": "test_tool",
            "inputs": {"param": "value"},
            "status": "success",
        },
    )
    assert response.status_code in [403, 404, 405]


def test_viewer_cannot_approve_requests(
    client: TestClient,
    viewer_token: str,
    session: Session,
):
    """Viewer cannot approve or deny approvals."""
    approval = Approval(
        approval_id="test-approval-123",
        tool="test_tool",
        inputs={"param": "value"},
        status=ApprovalStatus.PENDING,
    )
    session.add(approval)
    session.commit()

    response = client.post(
        "/api/approvals/test-approval-123/decide",
        headers={"Authorization": (f"Bearer {viewer_token}")},
        json={
            "approved": True,
            "reason": "Looks good",
        },
    )
    assert response.status_code == 403
    assert "Permission required" in response.json()["detail"]


def test_viewer_cannot_delete_datasets(
    client: TestClient,
    viewer_token: str,
    session: Session,
    admin_user: User,
):
    """Viewer cannot delete datasets."""
    dataset = Dataset(
        name="Test Dataset",
        description="Test",
        created_by=admin_user.id,
    )
    session.add(dataset)
    session.commit()
    session.refresh(dataset)

    response = client.delete(
        f"/api/datasets/{dataset.id}",
        headers={"Authorization": (f"Bearer {viewer_token}")},
    )
    assert response.status_code == 403


def test_viewer_cannot_create_datasets(
    client: TestClient,
    viewer_token: str,
):
    """Viewer cannot create datasets."""
    response = client.post(
        "/api/datasets",
        headers={"Authorization": (f"Bearer {viewer_token}")},
        json={
            "name": "New Dataset",
            "description": "Test dataset",
        },
    )
    assert response.status_code == 403


def test_viewer_cannot_update_datasets(
    client: TestClient,
    viewer_token: str,
    session: Session,
    admin_user: User,
):
    """Viewer cannot update datasets."""
    dataset = Dataset(
        name="Test Dataset",
        description="Test",
        created_by=admin_user.id,
    )
    session.add(dataset)
    session.commit()
    session.refresh(dataset)

    response = client.patch(
        f"/api/datasets/{dataset.id}",
        headers={"Authorization": (f"Bearer {viewer_token}")},
        json={"name": "Updated Name"},
    )
    assert response.status_code == 403


def test_viewer_cannot_create_test_cases(
    client: TestClient,
    viewer_token: str,
    session: Session,
    admin_user: User,
):
    """Viewer cannot create test cases."""
    dataset = Dataset(
        name="Test Dataset",
        created_by=admin_user.id,
    )
    session.add(dataset)
    session.commit()
    session.refresh(dataset)

    response = client.post(
        f"/api/datasets/{dataset.id}/tests",
        headers={"Authorization": (f"Bearer {viewer_token}")},
        json={
            "dataset_id": dataset.id,
            "name": "Test Case",
            "tool": "test_tool",
            "inputs": {"param": "value"},
        },
    )
    assert response.status_code == 403


def test_viewer_cannot_delete_test_cases(
    client: TestClient,
    viewer_token: str,
):
    """Viewer cannot delete test cases."""
    response = client.delete(
        "/api/datasets/1/tests/1",
        headers={"Authorization": (f"Bearer {viewer_token}")},
    )
    assert response.status_code in [403, 404]


def test_viewer_cannot_run_test_datasets(
    client: TestClient,
    viewer_token: str,
    session: Session,
    admin_user: User,
):
    """Viewer cannot run test datasets."""
    dataset = Dataset(
        name="Test Dataset",
        created_by=admin_user.id,
    )
    session.add(dataset)
    session.commit()
    session.refresh(dataset)

    response = client.post(
        f"/api/datasets/{dataset.id}/runs",
        headers={"Authorization": (f"Bearer {viewer_token}")},
        json={
            "dataset_id": dataset.id,
            "name": "Test Run",
        },
    )
    assert response.status_code == 403


def test_viewer_cannot_export_audit_logs(
    client: TestClient,
    viewer_token: str,
):
    """Viewer cannot export audit logs."""
    response = client.get(
        "/api/audit/export",
        headers={"Authorization": (f"Bearer {viewer_token}")},
    )
    assert response.status_code in [403, 404]


def test_viewer_cannot_modify_cost_limits(
    client: TestClient,
    viewer_token: str,
):
    """Viewer cannot modify cost limits."""
    response = client.post(
        "/api/costs/limit",
        headers={"Authorization": (f"Bearer {viewer_token}")},
        json={"limit": 1000.0},
    )
    assert response.status_code in [403, 404, 405]


def test_viewer_cannot_create_users(
    client: TestClient,
    viewer_token: str,
):
    """Viewer cannot create other users."""
    response = client.post(
        "/api/users",
        headers={"Authorization": (f"Bearer {viewer_token}")},
        json={
            "email": "newuser@example.com",
            "password": "password123",
            "name": "New User",
            "role": "viewer",
        },
    )
    assert response.status_code in [403, 404, 405]


def test_admin_cannot_create_user_with_weak_password(
    client: TestClient,
    admin_token: str,
):
    """User creation enforces password validation."""
    response = client.post(
        "/api/users",
        headers={"Authorization": (f"Bearer {admin_token}")},
        json={
            "email": "weak-user@example.com",
            "password": "1",
            "name": "Weak User",
            "role": "viewer",
        },
    )
    assert response.status_code == 422


def test_viewer_cannot_delete_users(
    client: TestClient,
    viewer_token: str,
):
    """Viewer cannot delete users."""
    response = client.delete(
        "/api/users/999",
        headers={"Authorization": (f"Bearer {viewer_token}")},
    )
    assert response.status_code in [403, 404, 405]


def test_viewer_cannot_modify_user_roles(
    client: TestClient,
    viewer_token: str,
):
    """Viewer cannot modify user roles."""
    response = client.patch(
        "/api/users/999/role",
        headers={"Authorization": (f"Bearer {viewer_token}")},
        json={"role": "admin"},
    )
    assert response.status_code in [403, 404, 405]


def test_viewer_cannot_access_admin_endpoints(
    client: TestClient,
    viewer_token: str,
):
    """Viewer cannot access admin-only endpoints."""
    endpoints = [
        "/api/admin/stats",
        "/api/admin/config",
        "/api/admin/users",
    ]

    for endpoint in endpoints:
        response = client.get(
            endpoint,
            headers={"Authorization": (f"Bearer {viewer_token}")},
        )
        assert response.status_code in [403, 404]


def test_viewer_can_read_own_data(
    client: TestClient,
    viewer_token: str,
):
    """Viewer can read their own data."""
    response = client.get(
        "/api/auth/me",
        headers={"Authorization": (f"Bearer {viewer_token}")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["role"] == "viewer"
