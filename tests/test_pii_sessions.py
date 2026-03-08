"""Tests for PII session management endpoints."""

import uuid
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
import pytest
from sqlmodel import Session

from server.models import PIIPermission, PIISession, User, UserPIIPermissions

pytest_plugins = ("tests.pii_api_test_support",)


@pytest.fixture(name="user_with_pii_permissions")
def user_with_pii_permissions_fixture(session: Session, regular_user: User, admin_user: User):
    """Create a user with PII permissions."""
    _ = session
    permissions = [
        PIIPermission.PII_STORE,
        PIIPermission.PII_RETRIEVE,
        PIIPermission.PII_AUDIT_READ,
    ]

    assert regular_user.id is not None
    assert admin_user.id is not None
    for perm in permissions:
        permission = UserPIIPermissions(
            user_id=regular_user.id,
            permission=perm.value,
            granted_by=admin_user.id,
            reason="Test permissions",
        )
        session.add(permission)

    session.commit()
    return regular_user


class TestPIISessionEndpoints:
    """Test PII session management endpoints."""

    def test_create_pii_session_requires_authentication(self, client: TestClient):
        """POST /pii/sessions requires authentication."""
        response = client.post(
            "/api/pii/sessions",
            json={
                "session_id": "test-session",
                "user_id": "user@example.com",
                "purpose": "Testing",
            },
        )
        assert response.status_code == 401

    def test_create_pii_session_requires_pii_store_permission(
        self, client: TestClient, user_token: str
    ):
        """POST /pii/sessions requires pii:store permission."""
        response = client.post(
            "/api/pii/sessions",
            json={
                "session_id": "test-session",
                "user_id": "user@example.com",
                "purpose": "Testing",
            },
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403
        assert "pii:store" in response.json()["detail"]

    def test_create_pii_session_success(
        self,
        client: TestClient,
        session: Session,
        user_with_pii_permissions: User,
        user_token: str,
    ):
        """Successfully create a PII session."""
        _ = session
        _ = user_with_pii_permissions
        session_id = str(uuid.uuid4())
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

        response = client.post(
            "/api/pii/sessions",
            json={
                "session_id": session_id,
                "user_id": "user@example.com",
                "agent_id": "agent-123",
                "purpose": "Customer support",
                "expires_at": expires_at.isoformat(),
            },
            headers={"Authorization": f"Bearer {user_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["session_id"] == session_id
        assert data["user_id"] == "user@example.com"
        assert data["is_active"] is True
        assert "id" in data
        assert "created_at" in data

    def test_create_pii_session_rejects_owner_mismatch(
        self,
        client: TestClient,
        user_with_pii_permissions: User,
        user_token: str,
    ):
        """Non-admin users cannot create sessions for other owners."""
        _ = user_with_pii_permissions
        response = client.post(
            "/api/pii/sessions",
            json={
                "session_id": str(uuid.uuid4()),
                "user_id": "other-user@example.com",
                "purpose": "Testing owner scope",
            },
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403
        assert "must match authenticated user" in response.json()["detail"].lower()

    def test_create_pii_session_admin_bypass(
        self, client: TestClient, session: Session, admin_token: str
    ):
        """Admin can create PII session without explicit permission."""
        _ = session
        session_id = str(uuid.uuid4())

        response = client.post(
            "/api/pii/sessions",
            json={
                "session_id": session_id,
                "user_id": "test@example.com",
                "purpose": "Admin access",
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert response.status_code == 200
        assert response.json()["session_id"] == session_id

    def test_list_pii_sessions_requires_authentication(self, client: TestClient):
        """GET /pii/sessions requires authentication."""
        response = client.get("/api/pii/sessions")
        assert response.status_code == 401

    def test_list_pii_sessions_requires_audit_read_permission(
        self, client: TestClient, user_token: str
    ):
        """GET /pii/sessions requires pii:audit_read permission."""
        response = client.get(
            "/api/pii/sessions",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403
        assert "pii:audit_read" in response.json()["detail"]

    def test_list_pii_sessions_success(
        self, client: TestClient, session: Session, admin_token: str
    ):
        """Successfully list PII sessions."""
        pii_session = PIISession(
            session_id="test-session-1",
            user_id="user@example.com",
            purpose="Testing",
        )
        session.add(pii_session)
        session.commit()

        response = client.get(
            "/api/pii/sessions",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 1
        assert any(s["session_id"] == "test-session-1" for s in data)

    def test_list_pii_sessions_filter_by_user_id(
        self, client: TestClient, session: Session, admin_token: str
    ):
        """Filter PII sessions by user_id."""
        session.add(PIISession(session_id="sess-1", user_id="user1@example.com", purpose="Test"))
        session.add(PIISession(session_id="sess-2", user_id="user2@example.com", purpose="Test"))
        session.commit()

        response = client.get(
            "/api/pii/sessions?user_id=user1@example.com",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert all(s["user_id"] == "user1@example.com" for s in data)

    def test_list_pii_sessions_scoped_to_authenticated_user(
        self,
        client: TestClient,
        session: Session,
        user_with_pii_permissions: User,
        user_token: str,
    ):
        """Scoped reads only return sessions owned by the current non-admin user."""
        _ = user_with_pii_permissions
        session.add(PIISession(session_id="sess-own", user_id="user@example.com", purpose="Own"))
        session.add(
            PIISession(session_id="sess-other", user_id="other@example.com", purpose="Other")
        )
        session.commit()

        response = client.get(
            "/api/pii/sessions",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert all(s["user_id"] == "user@example.com" for s in data)

    def test_list_pii_sessions_rejects_foreign_user_filter_when_scoped(
        self,
        client: TestClient,
        user_with_pii_permissions: User,
        user_token: str,
    ):
        """Scoped reads deny explicit foreign user filters for non-admin users."""
        _ = user_with_pii_permissions
        response = client.get(
            "/api/pii/sessions?user_id=other@example.com",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403
        assert "scoped reads enabled" in response.json()["detail"].lower()

    def test_list_pii_sessions_filter_by_is_active(
        self, client: TestClient, session: Session, admin_token: str
    ):
        """Filter PII sessions by is_active status."""
        active_session = PIISession(
            session_id="active-sess", user_id="user@example.com", purpose="Test", is_active=True
        )
        inactive_session = PIISession(
            session_id="inactive-sess",
            user_id="user@example.com",
            purpose="Test",
            is_active=False,
        )
        session.add(active_session)
        session.add(inactive_session)
        session.commit()

        response = client.get(
            "/api/pii/sessions?is_active=true",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert all(s["is_active"] is True for s in data)

    def test_list_pii_sessions_pagination(
        self, client: TestClient, session: Session, admin_token: str
    ):
        """Pagination works for PII sessions."""
        for i in range(10):
            session.add(
                PIISession(session_id=f"sess-{i}", user_id="user@example.com", purpose=f"Test {i}")
            )
        session.commit()

        response = client.get(
            "/api/pii/sessions?limit=5&offset=0",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data) <= 5

    def test_delete_pii_session_requires_authentication(self, client: TestClient):
        """DELETE /pii/sessions/{id} requires authentication."""
        response = client.delete("/api/pii/sessions/test-session")
        assert response.status_code == 401

    def test_delete_pii_session_requires_clear_session_permission(
        self, client: TestClient, user_token: str
    ):
        """DELETE /pii/sessions/{id} requires pii:clear_session permission."""
        response = client.delete(
            "/api/pii/sessions/test-session",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403
        assert "pii:clear_session" in response.json()["detail"]

    def test_delete_pii_session_not_found(self, client: TestClient, admin_token: str):
        """DELETE returns 404 for nonexistent session."""
        response = client.delete(
            "/api/pii/sessions/nonexistent-session",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    def test_delete_pii_session_success(
        self, client: TestClient, session: Session, admin_token: str
    ):
        """Successfully delete a PII session."""
        pii_session = PIISession(
            session_id="delete-me", user_id="user@example.com", purpose="Test", is_active=True
        )
        session.add(pii_session)
        session.commit()

        response = client.delete(
            "/api/pii/sessions/delete-me",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert response.status_code == 200
        assert response.json()["session_id"] == "delete-me"

        session.refresh(pii_session)
        assert pii_session.is_active is False

    def test_delete_pii_session_rejects_foreign_owner_when_scoped(
        self,
        request: pytest.FixtureRequest,
        session: Session,
        user_token: str,
    ):
        """Scoped session clear denies non-admin users for foreign owners."""
        client = request.getfixturevalue("client")
        regular_user = request.getfixturevalue("regular_user")
        admin_user = request.getfixturevalue("admin_user")
        assert regular_user.id is not None
        assert admin_user.id is not None
        session.add(
            UserPIIPermissions(
                user_id=regular_user.id,
                permission=PIIPermission.PII_CLEAR_SESSION.value,
                granted_by=admin_user.id,
                reason="Test scoped clear permission",
            )
        )
        session.add(
            PIISession(
                session_id="foreign-session",
                user_id="other-user@example.com",
                purpose="Foreign owner session",
                is_active=True,
            )
        )
        session.commit()

        response = client.delete(
            "/api/pii/sessions/foreign-session",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403
        assert "session access denied" in response.json()["detail"].lower()

    def test_redact_requires_pii_store_permission(
        self,
        client: TestClient,
        user_token: str,
    ):
        """PII redaction requires pii:store permission."""
        response = client.post(
            "/api/pii/redact",
            json={
                "session_id": "any-session",
                "text": "john@example.com",
                "score_threshold": 0.4,
            },
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403
        assert "pii:store" in response.json()["detail"]
