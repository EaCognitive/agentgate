"""Tests for PII permission management endpoints."""

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import PIIPermission, User, UserPIIPermissions

pytest_plugins = ("tests.pii_api_test_support",)


class TestPIIPermissionEndpoints:
    """Test PII permission management endpoints."""

    def test_list_permissions_requires_authentication(self, client: TestClient):
        """GET /pii/permissions requires authentication."""
        response = client.get("/api/pii/permissions")
        assert response.status_code == 401

    def test_list_permissions_requires_admin(self, client: TestClient, user_token: str):
        """GET /pii/permissions requires admin role."""
        response = client.get(
            "/api/pii/permissions",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403

    def test_list_permissions_success(
        self, client: TestClient, session: Session, admin_token: str, regular_user: User
    ):
        """Successfully list PII permissions."""
        assert regular_user.id is not None
        permission = UserPIIPermissions(
            user_id=regular_user.id,
            permission=PIIPermission.PII_STORE.value,
            granted_by=1,
            reason="Test",
        )
        session.add(permission)
        session.commit()

        response = client.get(
            "/api/pii/permissions",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 1

    def test_list_permissions_filter_by_user_id(
        self, client: TestClient, session: Session, admin_token: str, regular_user: User
    ):
        """Filter permissions by user_id."""
        assert regular_user.id is not None
        permission = UserPIIPermissions(
            user_id=regular_user.id,
            permission=PIIPermission.PII_STORE.value,
            granted_by=1,
            reason="Test",
        )
        session.add(permission)
        session.commit()

        response = client.get(
            f"/api/pii/permissions?user_id={regular_user.id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert all(p["user_id"] == regular_user.id for p in data)

    def test_list_available_permissions_requires_authentication(self, client: TestClient):
        """GET /pii/permissions/available requires authentication."""
        response = client.get("/api/pii/permissions/available")
        assert response.status_code == 401

    def test_list_available_permissions_success(self, client: TestClient, user_token: str):
        """Successfully list available PII permissions."""
        response = client.get(
            "/api/pii/permissions/available",
            headers={"Authorization": f"Bearer {user_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "permissions" in data
        assert len(data["permissions"]) > 0
        assert all("value" in p and "name" in p for p in data["permissions"])

    def test_grant_permission_requires_authentication(self, client: TestClient):
        """POST /pii/permissions requires authentication."""
        response = client.post(
            "/api/pii/permissions",
            json={
                "user_id": 1,
                "permission": "pii:store",
                "reason": "Test",
            },
        )
        assert response.status_code == 401

    def test_grant_permission_requires_admin(self, client: TestClient, user_token: str):
        """POST /pii/permissions requires admin role."""
        response = client.post(
            "/api/pii/permissions",
            json={
                "user_id": 1,
                "permission": "pii:store",
                "reason": "Test",
            },
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403

    def test_grant_permission_invalid_permission(
        self, client: TestClient, admin_token: str, regular_user: User
    ):
        """Grant permission fails with invalid permission value."""
        response = client.post(
            "/api/pii/permissions",
            json={
                "user_id": regular_user.id,
                "permission": "invalid:permission",
                "reason": "Test",
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert response.status_code == 400
        assert "Invalid permission" in response.json()["detail"]

    def test_grant_permission_success(
        self, client: TestClient, admin_token: str, regular_user: User
    ):
        """Successfully grant a PII permission."""
        response = client.post(
            "/api/pii/permissions",
            json={
                "user_id": regular_user.id,
                "permission": PIIPermission.PII_STORE.value,
                "reason": "Customer support access",
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == regular_user.id
        assert data["permission"] == PIIPermission.PII_STORE.value
        assert data["reason"] == "Customer support access"

    def test_grant_permission_with_expiration(
        self, client: TestClient, admin_token: str, regular_user: User
    ):
        """Grant permission with expiration date."""
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)

        response = client.post(
            "/api/pii/permissions",
            json={
                "user_id": regular_user.id,
                "permission": PIIPermission.PII_RETRIEVE.value,
                "reason": "Temporary access",
                "expires_at": expires_at.isoformat(),
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["expires_at"] is not None

    def test_grant_permission_duplicate_fails(
        self, client: TestClient, session: Session, admin_token: str, regular_user: User
    ):
        """Cannot grant same permission twice."""
        assert regular_user.id is not None
        permission = UserPIIPermissions(
            user_id=regular_user.id,
            permission=PIIPermission.PII_STORE.value,
            granted_by=1,
            reason="Test",
        )
        session.add(permission)
        session.commit()

        response = client.post(
            "/api/pii/permissions",
            json={
                "user_id": regular_user.id,
                "permission": PIIPermission.PII_STORE.value,
                "reason": "Duplicate attempt",
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert response.status_code == 400
        assert "already granted" in response.json()["detail"]

    def test_revoke_permission_requires_authentication(self, client: TestClient):
        """DELETE /pii/permissions/{id} requires authentication."""
        response = client.delete("/api/pii/permissions/1")
        assert response.status_code == 401

    def test_revoke_permission_requires_admin(self, client: TestClient, user_token: str):
        """DELETE /pii/permissions/{id} requires admin role."""
        response = client.delete(
            "/api/pii/permissions/1",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403

    def test_revoke_permission_not_found(self, client: TestClient, admin_token: str):
        """DELETE returns 404 for nonexistent permission."""
        response = client.delete(
            "/api/pii/permissions/99999",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    def test_revoke_permission_success(
        self, client: TestClient, session: Session, admin_token: str, regular_user: User
    ):
        """Successfully revoke a PII permission."""
        assert regular_user.id is not None
        permission = UserPIIPermissions(
            user_id=regular_user.id,
            permission=PIIPermission.PII_STORE.value,
            granted_by=1,
            reason="Test",
        )
        session.add(permission)
        session.commit()
        session.refresh(permission)

        response = client.delete(
            f"/api/pii/permissions/{permission.id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert response.status_code == 200
        assert response.json()["message"] == "Permission revoked"
