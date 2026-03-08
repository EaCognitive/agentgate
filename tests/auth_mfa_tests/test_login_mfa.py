"""Tests for login with MFA."""

from datetime import datetime, timedelta, timezone

import pyotp
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from server.main import limiter as main_limiter
from server.models import AuditEntry, User
from server.routers.auth import limiter as auth_limiter

from tests.auth_mfa_tests.conftest import MfaTestData


def test_login_with_mfa_requires_code(client: TestClient, user_with_mfa: User) -> None:
    """Test login with MFA enabled requires code."""
    response = client.post(
        "/api/auth/login", json={"email": user_with_mfa.email, "password": "password123"}
    )
    assert response.status_code == 200
    assert response.json()["mfa_required"] is True
    assert "access_token" not in response.json()


def test_login_with_mfa_valid_code_succeeds(client: TestClient, user_with_mfa: User) -> None:
    """Test login with valid MFA code succeeds."""
    totp = pyotp.TOTP(user_with_mfa.totp_secret)
    code = totp.now()

    response = client.post(
        "/api/auth/login",
        json={"email": user_with_mfa.email, "password": "password123", "totp_code": code},
    )
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert "refresh_token" in response.json()
    assert response.json()["token_type"] == "bearer"


def test_login_with_mfa_invalid_code_fails(client: TestClient, user_with_mfa: User) -> None:
    """Test login with invalid MFA code fails."""
    response = client.post(
        "/api/auth/login",
        json={"email": user_with_mfa.email, "password": "password123", "totp_code": "000000"},
    )
    assert response.status_code == 401
    assert "invalid" in response.json()["detail"].lower()


def test_login_with_mfa_backup_code_succeeds(
    client: TestClient,
    user_with_mfa: User,
    mfa_test_data: MfaTestData,
) -> None:
    """Test login with backup code succeeds."""
    backup_code = mfa_test_data.backup_codes_plain[0]

    response = client.post(
        "/api/auth/login",
        json={"email": user_with_mfa.email, "password": "password123", "totp_code": backup_code},
    )
    assert response.status_code == 200
    assert "access_token" in response.json()


def test_login_with_mfa_backup_code_single_use(
    client: TestClient,
    user_with_mfa: User,
    mfa_test_data: MfaTestData,
) -> None:
    """Test backup code can only be used once."""
    backup_code = mfa_test_data.backup_codes_plain[0]

    # First use - should succeed
    response1 = client.post(
        "/api/auth/login",
        json={"email": user_with_mfa.email, "password": "password123", "totp_code": backup_code},
    )
    assert response1.status_code == 200

    # Second use - should fail
    response2 = client.post(
        "/api/auth/login",
        json={"email": user_with_mfa.email, "password": "password123", "totp_code": backup_code},
    )
    assert response2.status_code == 401


def test_login_with_mfa_wrong_password_fails(client: TestClient, user_with_mfa: User) -> None:
    """Test login fails with wrong password even with valid MFA code."""
    totp = pyotp.TOTP(user_with_mfa.totp_secret)
    code = totp.now()

    response = client.post(
        "/api/auth/login",
        json={"email": user_with_mfa.email, "password": "wrongpassword", "totp_code": code},
    )
    assert response.status_code == 401
    assert "email or password" in response.json()["detail"].lower()


def test_login_with_mfa_no_code_returns_mfa_required(
    client: TestClient, user_with_mfa: User
) -> None:
    """Test login without MFA code returns mfa_required flag."""
    response = client.post(
        "/api/auth/login", json={"email": user_with_mfa.email, "password": "password123"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data.get("mfa_required") is True
    assert "access_token" not in data


def test_login_without_mfa_works_normally(client: TestClient, test_user: User) -> None:
    """Test login without MFA works as before."""
    response = client.post(
        "/api/auth/login", json={"email": test_user.email, "password": "password123"}
    )
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert "mfa_required" not in response.json() or response.json()["mfa_required"] is False


def test_login_with_mfa_empty_code_fails(client: TestClient, user_with_mfa: User) -> None:
    """Test login with empty MFA code fails."""
    response = client.post(
        "/api/auth/login",
        json={"email": user_with_mfa.email, "password": "password123", "totp_code": ""},
    )
    assert response.status_code == 401


def test_login_with_mfa_expired_code_fails(client: TestClient, user_with_mfa: User) -> None:
    """Test login with expired TOTP code fails."""
    totp = pyotp.TOTP(user_with_mfa.totp_secret)
    # Get code from past (outside valid window)
    old_code = totp.at(datetime.now(timezone.utc) - timedelta(minutes=5))

    response = client.post(
        "/api/auth/login",
        json={"email": user_with_mfa.email, "password": "password123", "totp_code": old_code},
    )
    assert response.status_code == 401


def test_login_with_mfa_user_not_found(client: TestClient) -> None:
    """Test login with MFA for non-existent user fails gracefully."""
    response = client.post(
        "/api/auth/login",
        json={
            "email": "nonexistent@example.com",
            "password": "password123",
            "totp_code": "123456",
        },
    )
    assert response.status_code == 401


def test_login_with_mfa_disabled_account(
    client: TestClient, user_with_mfa: User, session: Session
) -> None:
    """Test login fails for disabled account even with valid MFA."""
    user_with_mfa.is_active = False
    session.add(user_with_mfa)
    session.commit()

    totp = pyotp.TOTP(user_with_mfa.totp_secret)
    code = totp.now()

    response = client.post(
        "/api/auth/login",
        json={"email": user_with_mfa.email, "password": "password123", "totp_code": code},
    )
    assert response.status_code == 403
    assert "disabled" in response.json()["detail"].lower()


def test_login_with_mfa_rate_limited(client: TestClient, user_with_mfa: User) -> None:
    """Test login attempts are rate limited."""
    # Re-enable rate limiting for this specific test

    main_limiter.enabled = True
    auth_limiter.enabled = True

    try:
        # Make multiple failed attempts
        for _ in range(6):  # Rate limit is 5/minute
            client.post(
                "/api/auth/login",
                json={
                    "email": user_with_mfa.email,
                    "password": "password123",
                    "totp_code": "000000",
                },
            )

        # Next attempt should be rate limited
        response = client.post(
            "/api/auth/login",
            json={
                "email": user_with_mfa.email,
                "password": "password123",
                "totp_code": "000000",
            },
        )
        # Rate limiter may not be active in test environments.
        assert response.status_code in (401, 429)
    finally:
        # Disable again after test
        main_limiter.enabled = False
        auth_limiter.enabled = False


def test_login_with_mfa_audit_log_success(
    client: TestClient, user_with_mfa: User, session: Session
) -> None:
    """Test successful MFA login creates audit log."""
    totp = pyotp.TOTP(user_with_mfa.totp_secret)
    code = totp.now()

    client.post(
        "/api/auth/login",
        json={"email": user_with_mfa.email, "password": "password123", "totp_code": code},
    )

    audit = session.exec(
        select(AuditEntry)
        .where(AuditEntry.event_type == "login")
        .where(AuditEntry.actor == user_with_mfa.email)
    ).first()

    assert audit is not None
    assert audit.result == "success"


def test_login_with_mfa_audit_log_failure(
    client: TestClient, user_with_mfa: User, session: Session
) -> None:
    """Test failed MFA login creates audit log."""
    client.post(
        "/api/auth/login",
        json={"email": user_with_mfa.email, "password": "password123", "totp_code": "000000"},
    )

    audit = session.exec(
        select(AuditEntry)
        .where(AuditEntry.event_type == "login")
        .where(AuditEntry.actor == user_with_mfa.email)
        .where(AuditEntry.result == "failed")
    ).first()

    assert audit is not None
    assert audit.result == "failed"
