"""Tests for backup codes."""

import pyotp
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from server.models import AuditEntry, User

from tests.auth_mfa_tests.conftest import MfaTestData


def test_regenerate_backup_codes_with_password(
    client: TestClient, auth_token_with_mfa: str
) -> None:
    """Test regenerating backup codes with valid password."""
    response = client.post(
        "/api/auth/regenerate-backup-codes",
        json={"password": "password123"},
        headers={"Authorization": f"Bearer {auth_token_with_mfa}"},
    )
    assert response.status_code == 200
    assert "backup_codes" in response.json()
    assert len(response.json()["backup_codes"]) == 8


def test_regenerate_backup_codes_wrong_password_fails(
    client: TestClient, auth_token_with_mfa: str
) -> None:
    """Test regenerating backup codes with wrong password fails."""
    response = client.post(
        "/api/auth/regenerate-backup-codes",
        json={"password": "wrongpassword"},
        headers={"Authorization": f"Bearer {auth_token_with_mfa}"},
    )
    assert response.status_code == 401


def test_regenerate_backup_codes_replaces_old_codes(
    client: TestClient,
    user_with_mfa: User,
    mfa_test_data: MfaTestData,
) -> None:
    """Test regenerating backup codes invalidates old codes."""
    old_backup_code = mfa_test_data.backup_codes_plain[0]

    # Get token for first login

    totp = pyotp.TOTP(user_with_mfa.totp_secret)
    code = totp.now()
    response = client.post(
        "/api/auth/login",
        json={
            "email": user_with_mfa.email,
            "password": "password123",
            "totp_code": code,
        },
    )
    token = response.json()["access_token"]

    # Regenerate codes
    response = client.post(
        "/api/auth/regenerate-backup-codes",
        json={"password": "password123"},
        headers={"Authorization": f"Bearer {token}"},
    )

    # Old code should not work
    response = client.post(
        "/api/auth/login",
        json={
            "email": user_with_mfa.email,
            "password": "password123",
            "totp_code": old_backup_code,
        },
    )
    assert response.status_code == 401


def test_backup_codes_hashed_in_database(
    client: TestClient, auth_token_with_mfa: str, session: Session
) -> None:
    """Test backup codes are stored hashed."""
    response = client.post(
        "/api/auth/regenerate-backup-codes",
        json={"password": "password123"},
        headers={"Authorization": f"Bearer {auth_token_with_mfa}"},
    )
    plain_codes = response.json()["backup_codes"]

    user = session.exec(select(User).where(User.email == "mfa@example.com")).first()

    # Verify plain codes are not in database
    for plain_code in plain_codes:
        assert plain_code not in user.backup_codes


def test_backup_codes_unique(client: TestClient, auth_token_with_mfa: str) -> None:
    """Test all backup codes are unique."""
    response = client.post(
        "/api/auth/regenerate-backup-codes",
        json={"password": "password123"},
        headers={"Authorization": f"Bearer {auth_token_with_mfa}"},
    )
    codes = response.json()["backup_codes"]

    assert len(codes) == len(set(codes))


def test_backup_codes_format_valid(client: TestClient, auth_token_with_mfa: str) -> None:
    """Test backup codes have valid format."""
    response = client.post(
        "/api/auth/regenerate-backup-codes",
        json={"password": "password123"},
        headers={"Authorization": f"Bearer {auth_token_with_mfa}"},
    )
    codes = response.json()["backup_codes"]

    for code in codes:
        # Should be 8 characters, alphanumeric
        assert len(code) == 8
        assert code.isalnum()


def test_backup_codes_count_correct(client: TestClient, auth_token_with_mfa: str) -> None:
    """Test correct number of backup codes generated."""
    response = client.post(
        "/api/auth/regenerate-backup-codes",
        json={"password": "password123"},
        headers={"Authorization": f"Bearer {auth_token_with_mfa}"},
    )
    assert len(response.json()["backup_codes"]) == 8


def test_regenerate_backup_codes_audit_log(
    client: TestClient, auth_token_with_mfa: str, session: Session
) -> None:
    """Test regenerating backup codes creates audit log."""
    client.post(
        "/api/auth/regenerate-backup-codes",
        json={"password": "password123"},
        headers={"Authorization": f"Bearer {auth_token_with_mfa}"},
    )

    audit = session.exec(
        select(AuditEntry)
        .where(AuditEntry.event_type == "backup_codes_regenerated")
        .where(AuditEntry.actor == "mfa@example.com")
    ).first()

    assert audit is not None
    assert audit.result == "success"
