"""Tests for disabling MFA."""

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from server.models import AuditEntry, User


def test_disable_mfa_with_password_succeeds(
    client: TestClient, auth_token_with_mfa: str, session: Session
) -> None:
    """Test disabling MFA with correct password succeeds."""
    response = client.post(
        "/api/auth/disable-2fa",
        json={"password": "password123"},
        headers={"Authorization": f"Bearer {auth_token_with_mfa}"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "disabled"

    # Verify in database
    user = session.exec(select(User).where(User.email == "mfa@example.com")).first()
    assert user.totp_enabled is False
    assert user.totp_secret is None


def test_disable_mfa_wrong_password_fails(client: TestClient, auth_token_with_mfa: str) -> None:
    """Test disabling MFA with wrong password fails."""
    response = client.post(
        "/api/auth/disable-2fa",
        json={"password": "wrongpassword"},
        headers={"Authorization": f"Bearer {auth_token_with_mfa}"},
    )
    assert response.status_code == 401
    assert "password" in response.json()["detail"].lower()


def test_disable_mfa_not_enabled_fails(client: TestClient, auth_token: str) -> None:
    """Test disabling MFA when not enabled fails."""
    response = client.post(
        "/api/auth/disable-2fa",
        json={"password": "password123"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert response.status_code == 400
    assert "not enabled" in response.json()["detail"].lower()


def test_disable_mfa_removes_secret(
    client: TestClient, auth_token_with_mfa: str, session: Session
) -> None:
    """Test disabling MFA removes TOTP secret."""
    client.post(
        "/api/auth/disable-2fa",
        json={"password": "password123"},
        headers={"Authorization": f"Bearer {auth_token_with_mfa}"},
    )

    user = session.exec(select(User).where(User.email == "mfa@example.com")).first()
    assert user.totp_secret is None


def test_disable_mfa_removes_backup_codes(
    client: TestClient, auth_token_with_mfa: str, session: Session
) -> None:
    """Test disabling MFA removes backup codes."""
    client.post(
        "/api/auth/disable-2fa",
        json={"password": "password123"},
        headers={"Authorization": f"Bearer {auth_token_with_mfa}"},
    )

    user = session.exec(select(User).where(User.email == "mfa@example.com")).first()
    assert user.backup_codes is None or len(user.backup_codes) == 0


def test_disable_mfa_requires_authentication(client: TestClient) -> None:
    """Test disabling MFA requires authentication."""
    response = client.post("/api/auth/disable-2fa", json={"password": "password123"})
    assert response.status_code == 401


def test_disable_mfa_audit_log_created(
    client: TestClient, auth_token_with_mfa: str, session: Session
) -> None:
    """Test disabling MFA creates audit log."""
    client.post(
        "/api/auth/disable-2fa",
        json={"password": "password123"},
        headers={"Authorization": f"Bearer {auth_token_with_mfa}"},
    )

    audit = session.exec(
        select(AuditEntry)
        .where(AuditEntry.event_type == "2fa_disabled")
        .where(AuditEntry.actor == "mfa@example.com")
    ).first()

    assert audit is not None
    assert audit.result == "success"


def test_disable_mfa_can_reenable_later(client: TestClient, auth_token_with_mfa: str) -> None:
    """Test MFA can be re-enabled after disabling."""
    # Disable MFA
    client.post(
        "/api/auth/disable-2fa",
        json={"password": "password123"},
        headers={"Authorization": f"Bearer {auth_token_with_mfa}"},
    )

    # Re-enable MFA
    response = client.post(
        "/api/auth/enable-2fa", headers={"Authorization": f"Bearer {auth_token_with_mfa}"}
    )
    assert response.status_code == 200
    assert "secret" in response.json()
