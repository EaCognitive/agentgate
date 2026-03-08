"""Router-focused tests for auth registration/session lifecycle endpoints."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import RefreshToken, User, UserSession
from tests.router_test_support import bearer_headers, create_test_user

pytest_plugins = ("tests.router_test_support",)


@pytest.fixture(name="user")
def user_fixture(session: Session) -> User:
    """Create a test user for auth-registration routes."""
    return create_test_user(
        session,
        email="router-auth@test.com",
        name="Router Auth",
        password="Password123!",
        role="admin",
        is_active=True,
        totp_enabled=False,
    )


@pytest.fixture(name="auth_headers")
def auth_headers_fixture(user: User) -> dict[str, str]:
    """Return bearer token headers for the test user."""
    return bearer_headers(
        user,
        assurance="A2",
        expires_delta=timedelta(minutes=15),
    )


def test_check_mfa_status_unknown_email_returns_false(client: TestClient) -> None:
    """Unknown users should not disclose account existence via MFA check."""
    response = client.post(
        "/api/auth/check-mfa",
        json={"email": "unknown@test.com"},
    )

    assert response.status_code == 200
    assert response.json() == {"mfa_enabled": False}


def test_check_mfa_status_enabled_user_returns_true(
    client: TestClient,
    session: Session,
    user: User,
) -> None:
    """MFA check should return true for users with TOTP enabled."""
    user.totp_enabled = True
    session.add(user)
    session.commit()

    response = client.post(
        "/api/auth/check-mfa",
        json={"email": user.email},
    )

    assert response.status_code == 200
    assert response.json() == {"mfa_enabled": True}


def test_list_sessions_returns_current_session_first(
    client: TestClient,
    session: Session,
    user: User,
    auth_headers: dict[str, str],
) -> None:
    """`/api/auth/sessions` should order by recent activity and mark current session."""
    older = UserSession(
        session_id="sess-older",
        user_id=user.id,
        refresh_token="rt-older",
        last_active=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=10),
        revoked=False,
    )
    newer = UserSession(
        session_id="sess-newer",
        user_id=user.id,
        refresh_token="rt-newer",
        last_active=datetime.now(timezone.utc).replace(tzinfo=None),
        revoked=False,
    )
    session.add(older)
    session.add(newer)
    session.commit()

    response = client.get("/api/auth/sessions", headers=auth_headers)

    assert response.status_code == 200
    payload = response.json()
    assert len(payload) == 2
    assert payload[0]["id"] == "sess-newer"
    assert payload[0]["is_current"] is True
    assert payload[1]["id"] == "sess-older"
    assert payload[1]["is_current"] is False


def test_revoke_session_revokes_associated_refresh_token(
    client: TestClient,
    session: Session,
    user: User,
    auth_headers: dict[str, str],
) -> None:
    """Revoking a session should also revoke the linked refresh token."""
    refresh = RefreshToken(
        token="router-refresh-token",
        user_id=user.id,
        expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1),
        revoked=False,
    )
    session_record = UserSession(
        session_id="sess-revoke-target",
        user_id=user.id,
        refresh_token=refresh.token,
        revoked=False,
    )
    session.add(refresh)
    session.add(session_record)
    session.commit()

    response = client.delete(
        "/api/auth/sessions/sess-revoke-target",
        headers=auth_headers,
    )

    assert response.status_code == 200
    assert response.json() == {"status": "revoked"}

    session.refresh(session_record)
    session.refresh(refresh)
    assert session_record.revoked is True
    assert session_record.revoked_at is not None
    assert refresh.revoked is True
    assert refresh.revoked_at is not None
