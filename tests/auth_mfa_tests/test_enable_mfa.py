"""Tests for MFA enablement."""

import base64
from binascii import Error as BinasciiError
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from server.models import AuditEntry, User
from server.routers.auth import create_access_token
from server.routers.auth_utils import _get_password_hash_sync as get_password_hash
from server.utils.mfa import verify_backup_code


def test_enable_mfa_generates_secret_and_qr(client: TestClient, auth_token: str) -> None:
    """Test enabling MFA returns secret and QR code."""
    response = client.post(
        "/api/auth/enable-2fa", headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "secret" in data
    assert "qr_code" in data
    assert "backup_codes" in data
    assert len(data["backup_codes"]) == 8
    assert data["qr_code"].startswith("data:image/png;base64,")
    assert len(data["secret"]) == 32  # Base32 encoded secret


def test_enable_mfa_requires_authentication(client: TestClient) -> None:
    """Test enabling MFA without auth fails."""
    response = client.post("/api/auth/enable-2fa")
    assert response.status_code == 401


def test_enable_mfa_twice_fails(client: TestClient, auth_token: str) -> None:
    """Test enabling MFA when already initiated fails."""
    # Enable first time
    client.post("/api/auth/enable-2fa", headers={"Authorization": f"Bearer {auth_token}"})

    # Try again - should fail
    response = client.post(
        "/api/auth/enable-2fa", headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert response.status_code == 400
    assert "already initiated" in response.json()["detail"].lower()


def test_enable_mfa_stores_secret_in_database(
    client: TestClient, auth_token: str, session: Session
) -> None:
    """Test enabling MFA stores secret in database."""
    response = client.post(
        "/api/auth/enable-2fa", headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert response.status_code == 200

    # Check database
    user = session.exec(select(User).where(User.email == "test@example.com")).first()
    assert user is not None
    assert user.totp_secret is not None
    assert len(user.totp_secret) == 32


def test_enable_mfa_does_not_enable_until_verified(
    client: TestClient, auth_token: str, session: Session
) -> None:
    """Test MFA is not active until verification."""
    client.post("/api/auth/enable-2fa", headers={"Authorization": f"Bearer {auth_token}"})

    user = session.exec(select(User).where(User.email == "test@example.com")).first()
    assert user.totp_enabled is False


def test_enable_mfa_secret_is_unique_per_user(client: TestClient, session: Session) -> None:
    """Test each user gets a unique TOTP secret."""
    # Create two users
    user1 = User(
        email="user1@test.com",
        hashed_password=get_password_hash("password123"),
        name="User 1",
        role="admin",
    )
    user2 = User(
        email="user2@test.com",
        hashed_password=get_password_hash("password123"),
        name="User 2",
        role="viewer",
    )
    session.add(user1)
    session.add(user2)
    session.commit()

    # Login both users and enable MFA
    response1 = client.post(
        "/api/auth/login", json={"email": "user1@test.com", "password": "password123"}
    )
    token1 = response1.json()["access_token"]

    response2 = client.post(
        "/api/auth/login", json={"email": "user2@test.com", "password": "password123"}
    )
    token2 = response2.json()["access_token"]

    mfa1 = client.post("/api/auth/enable-2fa", headers={"Authorization": f"Bearer {token1}"})
    mfa2 = client.post("/api/auth/enable-2fa", headers={"Authorization": f"Bearer {token2}"})

    assert mfa1.json()["secret"] != mfa2.json()["secret"]


def test_enable_mfa_backup_codes_are_hashed(
    client: TestClient, auth_token: str, session: Session
) -> None:
    """Test backup codes are stored hashed (bcrypt) in database."""
    response = client.post(
        "/api/auth/enable-2fa", headers={"Authorization": f"Bearer {auth_token}"}
    )
    backup_codes = response.json()["backup_codes"]

    user = session.exec(select(User).where(User.email == "test@example.com")).first()

    # Verify codes in DB are bcrypt hashed (start with $2b$)
    for stored_hash in user.backup_codes:
        assert stored_hash.startswith("$2b$"), "Backup codes should be bcrypt hashed"
        assert stored_hash not in backup_codes, "Plain codes should not be stored"

    # Verify each plain code can be verified against stored hashes
    for plain_code in backup_codes:
        assert verify_backup_code(plain_code, user.backup_codes), (
            f"Plain code {plain_code} should verify"
        )


def test_enable_mfa_qr_code_format_valid(client: TestClient, auth_token: str) -> None:
    """Test QR code is valid base64 PNG data URI."""
    response = client.post(
        "/api/auth/enable-2fa", headers={"Authorization": f"Bearer {auth_token}"}
    )
    qr_code = response.json()["qr_code"]

    assert qr_code.startswith("data:image/png;base64,")

    # Extract base64 part and verify it's valid

    base64_part = qr_code.split(",")[1]
    try:
        base64.b64decode(base64_part)
    except (BinasciiError, ValueError):
        pytest.fail("Invalid base64 encoding in QR code")


def test_enable_mfa_secret_length_correct(client: TestClient, auth_token: str) -> None:
    """Test TOTP secret has correct length."""
    response = client.post(
        "/api/auth/enable-2fa", headers={"Authorization": f"Bearer {auth_token}"}
    )
    secret = response.json()["secret"]

    # Base32 secrets should be 32 characters
    assert len(secret) == 32
    # Should be valid base32

    try:
        base64.b32decode(secret)
    except (BinasciiError, ValueError):
        pytest.fail("Invalid base32 secret")


def test_enable_mfa_backup_codes_unique(client: TestClient, auth_token: str) -> None:
    """Test all backup codes are unique."""
    response = client.post(
        "/api/auth/enable-2fa", headers={"Authorization": f"Bearer {auth_token}"}
    )
    backup_codes = response.json()["backup_codes"]

    assert len(backup_codes) == len(set(backup_codes))


def test_enable_mfa_invalid_token_fails(client: TestClient) -> None:
    """Test enabling MFA with invalid token fails."""
    response = client.post(
        "/api/auth/enable-2fa", headers={"Authorization": "Bearer invalid_token"}
    )
    assert response.status_code == 401


def test_enable_mfa_expired_token_fails(client: TestClient, test_user: User) -> None:
    """Test enabling MFA with expired token fails."""

    # Create expired token
    expired_token = create_access_token(
        data={"sub": test_user.email, "role": test_user.role},
        expires_delta=timedelta(seconds=-1),
    )

    response = client.post(
        "/api/auth/enable-2fa", headers={"Authorization": f"Bearer {expired_token}"}
    )
    assert response.status_code == 401


def test_enable_mfa_different_users_different_secrets(client: TestClient, session: Session) -> None:
    """Test multiple enable calls for same user return same secret until verified."""
    user = User(
        email="multi@test.com",
        hashed_password=get_password_hash("password123"),
        name="Multi Test",
        role="admin",
    )
    session.add(user)
    session.commit()

    response = client.post(
        "/api/auth/login", json={"email": "multi@test.com", "password": "password123"}
    )
    token = response.json()["access_token"]

    # First enable
    client.post("/api/auth/enable-2fa", headers={"Authorization": f"Bearer {token}"})

    # If we try to enable again without verification, it should fail (already enabled/initiated)
    response2 = client.post("/api/auth/enable-2fa", headers={"Authorization": f"Bearer {token}"})
    assert response2.status_code == 400


def test_enable_mfa_does_not_change_existing_data(
    client: TestClient, auth_token: str, session: Session
) -> None:
    """Test enabling MFA doesn't change user's other data."""
    # Get original user data
    user_before = session.exec(select(User).where(User.email == "test@example.com")).first()
    original_email = user_before.email
    original_name = user_before.name
    original_role = user_before.role

    # Enable MFA
    client.post("/api/auth/enable-2fa", headers={"Authorization": f"Bearer {auth_token}"})

    # Verify other data unchanged
    session.refresh(user_before)
    assert user_before.email == original_email
    assert user_before.name == original_name
    assert user_before.role == original_role


def test_enable_mfa_audit_log_created(
    client: TestClient, auth_token: str, session: Session
) -> None:
    """Test enabling MFA creates audit log entry."""
    client.post("/api/auth/enable-2fa", headers={"Authorization": f"Bearer {auth_token}"})

    # Check audit log
    audit = session.exec(
        select(AuditEntry)
        .where(AuditEntry.event_type == "2fa_init")
        .where(AuditEntry.actor == "test@example.com")
    ).first()

    assert audit is not None
    assert audit.result == "success"
