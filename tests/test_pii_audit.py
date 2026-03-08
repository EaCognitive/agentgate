"""Tests for PII audit log endpoints."""

import uuid

from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import PIIAuditEntry, PIIEventType

pytest_plugins = ("tests.pii_api_test_support",)


class TestPIIAuditEndpoints:
    """Test PII audit log endpoints."""

    def test_list_audit_entries_requires_authentication(self, client: TestClient):
        """GET /pii/audit requires authentication."""
        response = client.get("/api/pii/audit")
        assert response.status_code == 401

    def test_list_audit_entries_requires_permission(self, client: TestClient, user_token: str):
        """GET /pii/audit requires pii:audit_read permission."""
        response = client.get(
            "/api/pii/audit",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403

    def test_list_audit_entries_success(
        self, client: TestClient, session: Session, admin_token: str
    ):
        """Successfully list audit entries."""
        audit_entry = PIIAuditEntry(
            event_id=str(uuid.uuid4()),
            event_type=PIIEventType.PII_STORE.value,
            user_id="test@example.com",
            session_id="test-session",
            success=True,
        )
        session.add(audit_entry)
        session.commit()

        response = client.get(
            "/api/pii/audit",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_list_audit_entries_filter_by_event_type(
        self, client: TestClient, session: Session, admin_token: str
    ):
        """Filter audit entries by event_type."""
        session.add(
            PIIAuditEntry(
                event_id=str(uuid.uuid4()),
                event_type=PIIEventType.PII_STORE.value,
                user_id="user@example.com",
                success=True,
            )
        )
        session.add(
            PIIAuditEntry(
                event_id=str(uuid.uuid4()),
                event_type=PIIEventType.PII_RETRIEVE.value,
                user_id="user@example.com",
                success=True,
            )
        )
        session.commit()

        response = client.get(
            f"/api/pii/audit?event_type={PIIEventType.PII_STORE.value}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert all(e["event_type"] == PIIEventType.PII_STORE.value for e in data)

    def test_list_audit_entries_filter_by_user_id(
        self, client: TestClient, session: Session, admin_token: str
    ):
        """Filter audit entries by user_id."""
        session.add(
            PIIAuditEntry(
                event_id=str(uuid.uuid4()),
                event_type=PIIEventType.PII_STORE.value,
                user_id="user1@example.com",
                success=True,
            )
        )
        session.add(
            PIIAuditEntry(
                event_id=str(uuid.uuid4()),
                event_type=PIIEventType.PII_STORE.value,
                user_id="user2@example.com",
                success=True,
            )
        )
        session.commit()

        response = client.get(
            "/api/pii/audit?user_id=user1@example.com",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert all(e["user_id"] == "user1@example.com" for e in data)

    def test_list_audit_entries_filter_by_success(
        self, client: TestClient, session: Session, admin_token: str
    ):
        """Filter audit entries by success status."""
        session.add(
            PIIAuditEntry(
                event_id=str(uuid.uuid4()),
                event_type=PIIEventType.PII_STORE.value,
                user_id="user@example.com",
                success=True,
            )
        )
        session.add(
            PIIAuditEntry(
                event_id=str(uuid.uuid4()),
                event_type=PIIEventType.PII_STORE.value,
                user_id="user@example.com",
                success=False,
                error_message="Test error",
            )
        )
        session.commit()

        response = client.get(
            "/api/pii/audit?success=false",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert all(e["success"] is False for e in data)

    def test_list_audit_entries_pagination(
        self, client: TestClient, session: Session, admin_token: str
    ):
        """Pagination works for audit entries."""
        for i in range(20):
            session.add(
                PIIAuditEntry(
                    event_id=str(uuid.uuid4()),
                    event_type=PIIEventType.PII_STORE.value,
                    user_id=f"user{i}@example.com",
                    success=True,
                )
            )
        session.commit()

        response = client.get(
            "/api/pii/audit?limit=10&offset=0",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data) <= 10

    def test_verify_audit_chain_requires_authentication(self, client: TestClient):
        """GET /pii/audit/verify-chain requires authentication."""
        response = client.get("/api/pii/audit/verify-chain")
        assert response.status_code == 401

    def test_verify_audit_chain_requires_permission(self, client: TestClient, user_token: str):
        """GET /pii/audit/verify-chain requires pii:audit_read permission."""
        response = client.get(
            "/api/pii/audit/verify-chain",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403

    def test_verify_audit_chain_empty_log(self, client: TestClient, admin_token: str):
        """Verify chain returns valid for empty log."""
        response = client.get(
            "/api/pii/audit/verify-chain",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        assert response.json()["valid"] is True

    def test_export_audit_log_requires_authentication(self, client: TestClient):
        """GET /pii/audit/export requires authentication."""
        response = client.get("/api/pii/audit/export")
        assert response.status_code == 401

    def test_export_audit_log_requires_permission(self, client: TestClient, user_token: str):
        """GET /pii/audit/export requires pii:export permission."""
        response = client.get(
            "/api/pii/audit/export",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403

    def test_export_audit_log_csv_format(
        self, client: TestClient, session: Session, admin_token: str
    ):
        """Export audit log in CSV format."""
        session.add(
            PIIAuditEntry(
                event_id=str(uuid.uuid4()),
                event_type=PIIEventType.PII_STORE.value,
                user_id="test@example.com",
                success=True,
            )
        )
        session.commit()

        response = client.get(
            "/api/pii/audit/export?format=csv",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/csv")
        assert "event_id,timestamp,event_type,user_id" in response.text

    def test_export_audit_log_json_format(
        self, client: TestClient, session: Session, admin_token: str
    ):
        """Export audit log in JSON format."""
        session.add(
            PIIAuditEntry(
                event_id=str(uuid.uuid4()),
                event_type=PIIEventType.PII_STORE.value,
                user_id="test@example.com",
                success=True,
            )
        )
        session.commit()

        response = client.get(
            "/api/pii/audit/export?format=json",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")
        data = response.json()
        assert "export_metadata" in data
        assert "entries" in data
        assert isinstance(data["entries"], list)
