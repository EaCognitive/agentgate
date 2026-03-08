"""Tests for PII compliance dashboard endpoints."""

import uuid

from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import PIIAuditEntry, PIIEventType

pytest_plugins = ("tests.pii_api_test_support",)


class TestComplianceDashboardEndpoints:
    """Test compliance dashboard endpoints."""

    def test_get_compliance_stats_requires_authentication(self, client: TestClient):
        """GET /pii/stats requires authentication."""
        response = client.get("/api/pii/stats")
        assert response.status_code == 401

    def test_get_compliance_stats_requires_permission(self, client: TestClient, user_token: str):
        """GET /pii/stats requires pii:audit_read permission."""
        response = client.get(
            "/api/pii/stats",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403

    def test_get_compliance_stats_success(
        self, client: TestClient, session: Session, admin_token: str
    ):
        """Successfully get compliance statistics."""
        # Add some audit entries to have stats
        for _ in range(5):
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
            "/api/pii/stats",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "total_pii_stored" in data
        assert "active_sessions" in data
        assert "integrity_failures" in data

    def test_get_access_report_requires_authentication(self, client: TestClient):
        """GET /pii/access-report requires authentication."""
        response = client.get("/api/pii/access-report")
        assert response.status_code == 401

    def test_get_access_report_requires_permission(self, client: TestClient, user_token: str):
        """GET /pii/access-report requires pii:export permission."""
        response = client.get(
            "/api/pii/access-report",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403

    def test_get_access_report_success(
        self, client: TestClient, session: Session, admin_token: str
    ):
        """Successfully get access report."""
        _ = session
        response = client.get(
            "/api/pii/access-report",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_get_compliance_checklist_requires_authentication(self, client: TestClient):
        """GET /pii/compliance-checklist requires authentication."""
        response = client.get("/api/pii/compliance-checklist")
        assert response.status_code == 401

    def test_get_compliance_checklist_requires_permission(
        self, client: TestClient, user_token: str
    ):
        """GET /pii/compliance-checklist requires pii:audit_read permission."""
        response = client.get(
            "/api/pii/compliance-checklist",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403

    def test_get_compliance_checklist_success(
        self, client: TestClient, session: Session, admin_token: str
    ):
        """Successfully get compliance checklist."""
        _ = session
        response = client.get(
            "/api/pii/compliance-checklist",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "hipaa" in data
        assert "soc2" in data
        assert "recommendations" in data
