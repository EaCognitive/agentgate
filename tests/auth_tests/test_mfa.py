"""MFA flow tests (Setup, Login with MFA, Backup codes)."""

from datetime import timedelta
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import User
from server.routers.auth import create_access_token
from server.routers.auth_utils import _get_password_hash_sync as get_password_hash
from server.utils.mfa import hash_backup_code


@patch("server.routers.auth_mfa.generate_totp_secret")
@patch("server.routers.auth_mfa.generate_qr_code")
@patch("server.routers.auth_mfa.generate_backup_codes")
def test_enable_2fa_flow(
    mock_backup_codes,
    mock_qr_code,
    mock_totp_secret,
    client: TestClient,
    auth_token: str,
):
    """Test complete 2FA enable flow."""
    mock_totp_secret.return_value = "TESTSECRET123456"
    mock_qr_code.return_value = "data:image/png;base64,ABC123"
    mock_backup_codes.return_value = ["CODE1", "CODE2", "CODE3"]

    response = client.post(
        "/api/auth/enable-2fa",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["secret"] == "TESTSECRET123456"
    assert "qr_code" in data
    assert len(data["backup_codes"]) == 3
    assert "message" in data


def test_enable_2fa_already_initiated(client: TestClient, session: Session):
    """Test enabling 2FA when setup already initiated."""

    user = User(
        email="mfa_initiated@test.com",
        hashed_password=get_password_hash("password123"),
        name="MFA Initiated",
        role="developer",
        totp_secret="ALREADY_INITIATED",  # Secret exists but not enabled
        totp_enabled=False,
    )
    session.add(user)
    session.commit()

    token = create_access_token(
        data={"sub": user.email, "role": user.role},
        expires_delta=timedelta(minutes=15),
    )

    response = client.post(
        "/api/auth/enable-2fa",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 400
    assert "already initiated" in response.json()["detail"].lower()


@patch("server.routers.auth_mfa.verify_totp_code")
def test_verify_2fa_success(
    mock_verify_totp,
    client: TestClient,
    session: Session,
):
    """Test successful 2FA verification."""

    # Create user with initiated but not enabled 2FA
    user = User(
        email="verify_2fa@test.com",
        hashed_password=get_password_hash("password123"),
        name="Verify 2FA",
        role="developer",
        totp_secret="TESTSECRET",
        totp_enabled=False,
    )
    session.add(user)
    session.commit()

    token = create_access_token(
        data={"sub": user.email, "role": user.role},
        expires_delta=timedelta(minutes=15),
    )

    mock_verify_totp.return_value = True

    response = client.post(
        "/api/auth/verify-2fa",
        json={"code": "123456"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "enabled"


def test_verify_2fa_when_already_enabled(client: TestClient, session: Session):
    """Test verifying 2FA when already enabled."""

    user = User(
        email="verify_enabled@test.com",
        hashed_password=get_password_hash("password123"),
        name="Verify Enabled",
        role="developer",
        totp_secret="TESTSECRET",
        totp_enabled=True,
    )
    session.add(user)
    session.commit()

    token = create_access_token(
        data={"sub": user.email, "role": user.role},
        expires_delta=timedelta(minutes=15),
    )

    response = client.post(
        "/api/auth/verify-2fa",
        json={"code": "123456"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 400
    assert "already enabled" in response.json()["detail"].lower()


def test_verify_2fa_not_initialized(client: TestClient, auth_token: str):
    """Test verifying 2FA when not initialized."""
    response = client.post(
        "/api/auth/verify-2fa",
        json={"code": "123456"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert response.status_code == 400
    assert "not initialized" in response.json()["detail"].lower()


@patch("server.routers.auth_mfa.verify_totp_code")
def test_verify_2fa_invalid_code(
    mock_verify_totp,
    client: TestClient,
    session: Session,
):
    """Test 2FA verification with invalid code."""

    user = User(
        email="verify_invalid@test.com",
        hashed_password=get_password_hash("password123"),
        name="Verify Invalid",
        role="developer",
        totp_secret="TESTSECRET",
        totp_enabled=False,
    )
    session.add(user)
    session.commit()

    token = create_access_token(
        data={"sub": user.email, "role": user.role},
        expires_delta=timedelta(minutes=15),
    )

    mock_verify_totp.return_value = False

    response = client.post(
        "/api/auth/verify-2fa",
        json={"code": "000000"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 400
    assert "invalid verification code" in response.json()["detail"].lower()


def test_disable_2fa_success(client: TestClient, session: Session):
    """Test successful 2FA disable."""

    user = User(
        email="disable_2fa@test.com",
        hashed_password=get_password_hash("password123"),
        name="Disable 2FA",
        role="developer",
        totp_secret="TESTSECRET",
        totp_enabled=True,
        backup_codes=["hash1", "hash2"],
    )
    session.add(user)
    session.commit()

    token = create_access_token(
        data={"sub": user.email, "role": user.role},
        expires_delta=timedelta(minutes=15),
    )

    response = client.post(
        "/api/auth/disable-2fa",
        json={"password": "password123"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "disabled"


def test_disable_2fa_not_enabled(client: TestClient, auth_token: str):
    """Test disabling 2FA when not enabled."""
    response = client.post(
        "/api/auth/disable-2fa",
        json={"password": "testpass123"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert response.status_code == 400
    assert "not enabled" in response.json()["detail"].lower()


def test_disable_2fa_wrong_password(client: TestClient, session: Session):
    """Test disabling 2FA with wrong password."""

    user = User(
        email="disable_wrong_pw@test.com",
        hashed_password=get_password_hash("password123"),
        name="Disable Wrong PW",
        role="developer",
        totp_secret="TESTSECRET",
        totp_enabled=True,
    )
    session.add(user)
    session.commit()

    token = create_access_token(
        data={"sub": user.email, "role": user.role},
        expires_delta=timedelta(minutes=15),
    )

    response = client.post(
        "/api/auth/disable-2fa",
        json={"password": "wrongpassword"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401
    assert "incorrect password" in response.json()["detail"].lower()


@patch("server.routers.auth_mfa.generate_backup_codes")
def test_regenerate_backup_codes_success(
    mock_backup_codes,
    client: TestClient,
    session: Session,
):
    """Test successful backup codes regeneration."""

    user = User(
        email="regen_codes@test.com",
        hashed_password=get_password_hash("password123"),
        name="Regen Codes",
        role="developer",
        totp_secret="TESTSECRET",
        totp_enabled=True,
        backup_codes=["old1", "old2"],
    )
    session.add(user)
    session.commit()

    token = create_access_token(
        data={"sub": user.email, "role": user.role},
        expires_delta=timedelta(minutes=15),
    )

    mock_backup_codes.return_value = ["NEW1", "NEW2", "NEW3"]

    response = client.post(
        "/api/auth/regenerate-backup-codes",
        json={"password": "password123"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data["backup_codes"]) == 3
    assert "message" in data


def test_regenerate_backup_codes_wrong_password(client: TestClient, session: Session):
    """Test regenerating backup codes with wrong password."""

    user = User(
        email="regen_wrong_pw@test.com",
        hashed_password=get_password_hash("password123"),
        name="Regen Wrong PW",
        role="developer",
        totp_secret="TESTSECRET",
        totp_enabled=True,
    )
    session.add(user)
    session.commit()

    token = create_access_token(
        data={"sub": user.email, "role": user.role},
        expires_delta=timedelta(minutes=15),
    )

    response = client.post(
        "/api/auth/regenerate-backup-codes",
        json={"password": "wrongpassword"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401
    assert "incorrect password" in response.json()["detail"].lower()


def test_login_with_mfa_returns_mfa_required(
    client: TestClient,
    session: Session,
):
    """Test login with MFA enabled returns mfa_required."""
    user = User(
        email="mfa_login@test.com",
        hashed_password=get_password_hash("password123"),
        name="MFA Login",
        role="developer",
        totp_secret="TESTSECRET",
        totp_enabled=True,
    )
    session.add(user)
    session.commit()

    response = client.post(
        "/api/auth/login",
        json={
            "email": user.email,
            "password": "password123",
            # No totp_code provided
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["mfa_required"] is True
    assert "access_token" not in data


def test_login_with_mfa_empty_code(client: TestClient, session: Session):
    """Test login with MFA and empty code string."""
    user = User(
        email="mfa_empty@test.com",
        hashed_password=get_password_hash("password123"),
        name="MFA Empty",
        role="developer",
        totp_secret="TESTSECRET",
        totp_enabled=True,
    )
    session.add(user)
    session.commit()

    response = client.post(
        "/api/auth/login",
        json={
            "email": user.email,
            "password": "password123",
            "totp_code": "   ",  # Empty/whitespace only
        },
    )
    assert response.status_code == 401
    assert "invalid 2fa code" in response.json()["detail"].lower()


@patch("server.routers.auth_utils.verify_totp_code")
def test_login_with_backup_code(
    mock_verify_totp,
    client: TestClient,
    session: Session,
):
    """Test login with backup code."""
    backup_hash = hash_backup_code("BACKUP1")
    secondary_hash = hash_backup_code("OTHER123")
    user = User(
        email="backup_login@test.com",
        hashed_password=get_password_hash("password123"),
        name="Backup Login",
        role="developer",
        totp_secret="TESTSECRET",
        totp_enabled=True,
        backup_codes=[backup_hash, secondary_hash],
    )
    session.add(user)
    session.commit()

    # TOTP fails, backup code succeeds
    mock_verify_totp.return_value = False

    response = client.post(
        "/api/auth/login",
        json={
            "email": user.email,
            "password": "password123",
            "totp_code": "BACKUP1",
        },
    )
    assert response.status_code == 200
    assert "access_token" in response.json()

    # Verify backup code was removed
    session.refresh(user)
    assert user.backup_codes is not None
    assert backup_hash not in user.backup_codes


@patch("server.routers.auth_utils.verify_totp_code")
def test_login_with_invalid_mfa_code(
    mock_verify_totp,
    client: TestClient,
    session: Session,
):
    """Test login with invalid MFA code."""
    user = User(
        email="invalid_mfa@test.com",
        hashed_password=get_password_hash("password123"),
        name="Invalid MFA",
        role="developer",
        totp_secret="TESTSECRET",
        totp_enabled=True,
    )
    session.add(user)
    session.commit()

    mock_verify_totp.return_value = False

    response = client.post(
        "/api/auth/login",
        json={
            "email": user.email,
            "password": "password123",
            "totp_code": "000000",
        },
    )
    assert response.status_code == 401
    assert "invalid 2fa code" in response.json()["detail"].lower()


@patch("server.routers.auth_utils.verify_totp_code")
def test_login_with_valid_totp_code(
    mock_verify_totp,
    client: TestClient,
    session: Session,
):
    """Test successful login with valid TOTP code."""
    user = User(
        email="valid_totp@test.com",
        hashed_password=get_password_hash("password123"),
        name="Valid TOTP",
        role="developer",
        totp_secret="TESTSECRET",
        totp_enabled=True,
    )
    session.add(user)
    session.commit()

    # Mock TOTP verification to succeed
    mock_verify_totp.return_value = True

    response = client.post(
        "/api/auth/login",
        json={
            "email": user.email,
            "password": "password123",
            "totp_code": "123456",
        },
    )
    assert response.status_code == 200
    assert "access_token" in response.json()
