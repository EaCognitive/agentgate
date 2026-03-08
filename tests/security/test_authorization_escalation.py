"""Privilege escalation prevention security tests.

Tests verify:
- Users cannot elevate their own role
- Token manipulation is detected
- Disabled users cannot authenticate
- Permission boundaries are enforced

Enterprise Engineering Protocols 2025
Zero trust security model
"""

from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import (
    Approval,
    ApprovalStatus,
    User,
)
from server.routers.auth_utils import _get_password_hash_sync as get_password_hash

pytest_plugins = ("tests.security.authz_test_support",)


# =============================================================
# PRIVILEGE ESCALATION PREVENTION (10 tests)
# =============================================================


def test_cannot_escalate_role_via_profile_update(
    client: TestClient,
    viewer_token: str,
):
    """User cannot escalate own role via profile update."""
    response = client.patch(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={"role": "admin"},
    )
    assert response.status_code in [
        403,
        404,
        405,
        422,
    ]


def test_cannot_escalate_role_via_user_update(
    client: TestClient,
    viewer_token: str,
    viewer_user: User,
):
    """User cannot escalate role via user update endpoint."""
    response = client.patch(
        f"/api/users/{viewer_user.id}",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={"role": "admin"},
    )
    assert response.status_code in [403, 404, 405]


def test_cannot_escalate_via_token_manipulation(
    client: TestClient,
    viewer_token: str,
):
    """Cannot bypass auth by manipulating token claims."""
    parts = viewer_token.split(".")
    if len(parts) == 3:
        corrupted_payload = parts[1][:-1] + ("A" if parts[1][-1] != "A" else "B")
        malicious_token = f"{parts[0]}.{corrupted_payload}.{parts[2]}"
    else:
        malicious_token = viewer_token + "corrupted"

    response = client.get(
        "/api/auth/me",
        headers={"Authorization": (f"Bearer {malicious_token}")},
    )
    assert response.status_code == 401


def test_cannot_bypass_auth_with_no_token(
    client: TestClient,
):
    """Cannot access protected endpoints without token."""
    response = client.get("/api/auth/me")
    assert response.status_code == 401


def test_cannot_bypass_auth_with_invalid_token(
    client: TestClient,
):
    """Cannot access endpoints with invalid token."""
    response = client.get(
        "/api/auth/me",
        headers={"Authorization": ("Bearer invalid_token_here")},
    )
    assert response.status_code == 401


def test_cannot_escalate_by_modifying_email(
    client: TestClient,
    viewer_token: str,
):
    """Cannot escalate by changing email to admin's."""
    response = client.patch(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={"email": "admin@example.com"},
    )
    assert response.status_code in [
        400,
        403,
        404,
        405,
        422,
    ]


def test_cannot_create_admin_user_via_registration(
    client: TestClient,
    admin_user: User,
):
    """Cannot register as admin (only first user becomes admin)."""
    _ = admin_user
    response = client.post(
        "/api/auth/register",
        json={
            "email": "newadmin@example.com",
            "password": "password123",
            "name": "New Admin",
            "role": "admin",
        },
    )

    if response.status_code in [200, 201]:
        data = response.json()
        assert data["role"] == "viewer"


def test_permission_boundaries_are_enforced(
    client: TestClient,
    viewer_token: str,
    session: Session,
):
    """Verify permission checks cannot be bypassed."""
    approval = Approval(
        approval_id="test-perm-check",
        tool="test_tool",
        inputs={},
        status=ApprovalStatus.PENDING,
    )
    session.add(approval)
    session.commit()

    response = client.post(
        "/api/approvals/test-perm-check/decide",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={"approved": True},
    )
    assert response.status_code == 403
    assert "Permission required" in response.json()["detail"]


def test_role_hierarchy_is_enforced(
    client: TestClient,
    viewer_token: str,
):
    """Lower roles cannot do higher-role actions."""
    response = client.delete(
        "/api/users/999",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert response.status_code in [403, 404, 405]


def test_disabled_user_cannot_authenticate(
    client: TestClient,
    session: Session,
):
    """Disabled users cannot authenticate."""
    user = User(
        email="disabled@example.com",
        name="Disabled User",
        hashed_password=get_password_hash("password123"),
        role="viewer",
        is_active=False,
    )
    session.add(user)
    session.commit()

    response = client.post(
        "/api/auth/login",
        json={
            "email": "disabled@example.com",
            "password": "password123",
        },
    )
    assert response.status_code == 403
    assert "disabled" in response.json()["detail"].lower()
