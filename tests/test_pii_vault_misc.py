"""Tests for PII vault management endpoints (encryption keys)."""

from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import EncryptionKeyRecord

pytest_plugins = ("tests.pii_api_test_support",)


class TestEncryptionKeyEndpoints:
    """Test encryption key management endpoints."""

    def test_list_encryption_keys_requires_authentication(self, client: TestClient):
        """GET /pii/keys requires authentication."""
        response = client.get("/api/pii/keys")
        assert response.status_code == 401

    def test_list_encryption_keys_requires_permission(self, client: TestClient, user_token: str):
        """GET /pii/keys requires key:view permission."""
        response = client.get(
            "/api/pii/keys",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403

    def test_list_encryption_keys_success(
        self, client: TestClient, session: Session, admin_token: str
    ):
        """Successfully list encryption keys."""
        key_record = EncryptionKeyRecord(
            key_id="test-key",
            algorithm="AES-256-GCM",
            is_active=True,
        )
        session.add(key_record)
        session.commit()

        response = client.get(
            "/api/pii/keys",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert any(k["key_id"] == "test-key" for k in data)

    def test_list_encryption_keys_filter_by_is_active(
        self, client: TestClient, session: Session, admin_token: str
    ):
        """Filter encryption keys by is_active status."""
        session.add(
            EncryptionKeyRecord(key_id="active-key", algorithm="AES-256-GCM", is_active=True)
        )
        session.add(
            EncryptionKeyRecord(key_id="inactive-key", algorithm="AES-256-GCM", is_active=False)
        )
        session.commit()

        response = client.get(
            "/api/pii/keys?is_active=false",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert all(k["is_active"] is False for k in data)

    def test_rotate_encryption_key_requires_authentication(self, client: TestClient):
        """POST /pii/keys/rotate requires authentication."""
        response = client.post("/api/pii/keys/rotate")
        assert response.status_code == 401

    def test_rotate_encryption_key_requires_permission(self, client: TestClient, user_token: str):
        """POST /pii/keys/rotate requires key:rotate permission."""
        response = client.post(
            "/api/pii/keys/rotate",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403

    def test_rotate_encryption_key_success(
        self, client: TestClient, session: Session, admin_token: str
    ):
        """Successfully rotate encryption key."""
        # Add initial key
        session.add(EncryptionKeyRecord(key_id="old-key", algorithm="AES-256-GCM", is_active=True))
        session.commit()

        response = client.post(
            "/api/pii/keys/rotate",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "new_key_id" in data
        assert "rotated_keys_count" in data
        assert data["new_key_id"] != "old-key"
