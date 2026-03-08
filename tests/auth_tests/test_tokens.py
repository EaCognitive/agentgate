"""Token revocation and management tests."""

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import RefreshToken, User


def test_revoke_refresh_token_success(
    client: TestClient, test_user: User, session: Session, auth_token: str
):
    """Test successful token revocation."""
    # Create a refresh token
    assert test_user.id is not None
    refresh_token = RefreshToken(
        token="token_to_revoke",
        user_id=test_user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        revoked=False,
    )
    session.add(refresh_token)
    session.commit()

    response = client.post(
        "/api/auth/revoke",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"refresh_token": "token_to_revoke"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "revoked"

    # Verify token was revoked
    session.refresh(refresh_token)
    assert refresh_token.revoked is True
    assert refresh_token.revoked_at is not None


def test_refresh_token_invalid_token(client: TestClient):
    """Test refresh with non-existent token."""
    response = client.post(
        "/api/auth/refresh",
        json={"refresh_token": "totally_invalid_token_xyz"},
    )
    assert response.status_code == 401
    assert "invalid refresh token" in response.json()["detail"].lower()
