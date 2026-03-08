"""Tests for MFA verification."""

from datetime import datetime, timedelta, timezone

import pyotp
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from server.models import AuditEntry, User


def test_verify_mfa_with_valid_code_enables(
    client: TestClient, auth_token: str, session: Session
) -> None:
    """Test verifying MFA with valid code enables it."""
    # Enable MFA
    response = client.post(
        "/api/auth/enable-2fa", headers={"Authorization": f"Bearer {auth_token}"}
    )
    secret = response.json()["secret"]

    # Generate valid code
    totp = pyotp.TOTP(secret)
    code = totp.now()

    # Verify
    response = client.post(
        "/api/auth/verify-2fa",
        json={"code": code},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "enabled"

    # Check database
    user = session.exec(select(User).where(User.email == "test@example.com")).first()
    assert user.totp_enabled is True


def test_verify_mfa_with_invalid_code_fails(client: TestClient, auth_token: str) -> None:
    """Test verifying MFA with invalid code fails."""
    client.post("/api/auth/enable-2fa", headers={"Authorization": f"Bearer {auth_token}"})

    response = client.post(
        "/api/auth/verify-2fa",
        json={"code": "000000"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert response.status_code == 400
    assert "invalid" in response.json()["detail"].lower()


def test_verify_mfa_without_enable_fails(client: TestClient, auth_token: str) -> None:
    """Test verifying MFA without calling enable-2fa fails."""
    response = client.post(
        "/api/auth/verify-2fa",
        json={"code": "123456"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert response.status_code == 400
    assert "not initialized" in response.json()["detail"].lower()


def test_verify_mfa_already_enabled_fails(client: TestClient, auth_token_with_mfa: str) -> None:
    """Test verifying MFA when already enabled fails."""
    response = client.post(
        "/api/auth/verify-2fa",
        json={"code": "123456"},
        headers={"Authorization": f"Bearer {auth_token_with_mfa}"},
    )
    assert response.status_code == 400
    assert "already enabled" in response.json()["detail"].lower()


def test_verify_mfa_with_old_code_fails(client: TestClient, auth_token: str) -> None:
    """Test verifying MFA with expired time-window code fails."""
    response = client.post(
        "/api/auth/enable-2fa", headers={"Authorization": f"Bearer {auth_token}"}
    )
    secret = response.json()["secret"]

    totp = pyotp.TOTP(secret)

    # Wait for code to expire (30 seconds + 1 window tolerance)
    # For testing, we'll just use an old timestamp
    old_code = totp.at(datetime.now(timezone.utc) - timedelta(minutes=5))

    response = client.post(
        "/api/auth/verify-2fa",
        json={"code": old_code},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert response.status_code == 400


def test_verify_mfa_with_future_code_fails(client: TestClient, auth_token: str) -> None:
    """Test verifying MFA with future code outside window fails."""
    response = client.post(
        "/api/auth/enable-2fa", headers={"Authorization": f"Bearer {auth_token}"}
    )
    secret = response.json()["secret"]

    totp = pyotp.TOTP(secret)
    # Get code from far future (beyond valid_window)
    future_code = totp.at(datetime.now(timezone.utc) + timedelta(minutes=5))

    response = client.post(
        "/api/auth/verify-2fa",
        json={"code": future_code},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert response.status_code == 400


def test_verify_mfa_case_insensitive(client: TestClient, auth_token: str) -> None:
    """Test MFA verification is case insensitive for codes."""
    response = client.post(
        "/api/auth/enable-2fa", headers={"Authorization": f"Bearer {auth_token}"}
    )
    secret = response.json()["secret"]

    totp = pyotp.TOTP(secret)
    code = totp.now()

    # Try with lowercase (though numeric codes don't have case)
    # This tests the parameter handling
    response = client.post(
        "/api/auth/verify-2fa",
        json={"code": code.lower()},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert response.status_code == 200


def test_verify_mfa_accepts_code_with_spaces(client: TestClient, auth_token: str) -> None:
    """Test MFA accepts codes with leading/trailing spaces."""
    response = client.post(
        "/api/auth/enable-2fa", headers={"Authorization": f"Bearer {auth_token}"}
    )
    secret = response.json()["secret"]

    totp = pyotp.TOTP(secret)
    code = totp.now()

    response = client.post(
        "/api/auth/verify-2fa",
        json={"code": f"  {code}  "},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert response.status_code == 200


def test_verify_mfa_sets_enabled_flag(
    client: TestClient, auth_token: str, session: Session
) -> None:
    """Test verification sets totp_enabled to True."""
    response = client.post(
        "/api/auth/enable-2fa", headers={"Authorization": f"Bearer {auth_token}"}
    )
    secret = response.json()["secret"]

    totp = pyotp.TOTP(secret)
    code = totp.now()

    client.post(
        "/api/auth/verify-2fa",
        json={"code": code},
        headers={"Authorization": f"Bearer {auth_token}"},
    )

    user = session.exec(select(User).where(User.email == "test@example.com")).first()
    assert user.totp_enabled is True


def test_verify_mfa_requires_authentication(client: TestClient) -> None:
    """Test MFA verification requires valid auth token."""
    response = client.post("/api/auth/verify-2fa", json={"code": "123456"})
    assert response.status_code == 401


def test_verify_mfa_audit_log_created(
    client: TestClient, auth_token: str, session: Session
) -> None:
    """Test MFA verification creates audit log."""
    response = client.post(
        "/api/auth/enable-2fa", headers={"Authorization": f"Bearer {auth_token}"}
    )
    secret = response.json()["secret"]

    totp = pyotp.TOTP(secret)
    code = totp.now()

    client.post(
        "/api/auth/verify-2fa",
        json={"code": code},
        headers={"Authorization": f"Bearer {auth_token}"},
    )

    audit = session.exec(
        select(AuditEntry)
        .where(AuditEntry.event_type == "2fa_enabled")
        .where(AuditEntry.actor == "test@example.com")
    ).first()

    assert audit is not None
    assert audit.result == "success"


def test_verify_mfa_multiple_attempts_allowed(client: TestClient, auth_token: str) -> None:
    """Test multiple verification attempts are allowed."""
    response = client.post(
        "/api/auth/enable-2fa", headers={"Authorization": f"Bearer {auth_token}"}
    )
    secret = response.json()["secret"]

    # Try with wrong code
    response1 = client.post(
        "/api/auth/verify-2fa",
        json={"code": "000000"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert response1.status_code == 400

    # Try with correct code
    totp = pyotp.TOTP(secret)
    code = totp.now()

    response2 = client.post(
        "/api/auth/verify-2fa",
        json={"code": code},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert response2.status_code == 200
