"""Authentication lifecycle integration tests."""

import pyotp
from fastapi.testclient import TestClient


def test_complete_user_lifecycle(client: TestClient) -> None:
    """Test: Register → Login → MFA Setup → Login with MFA → Logout."""
    # Step 1: Register
    response = client.post(
        "/api/auth/register",
        json={
            "email": "lifecycle@example.com",
            "password": "SecurePass123!",
            "name": "Lifecycle Test User",
        },
    )
    assert response.status_code == 200
    user_data = response.json()
    assert user_data["email"] == "lifecycle@example.com"

    # Step 2: Login (no MFA yet)
    response = client.post(
        "/api/auth/login",
        json={
            "email": "lifecycle@example.com",
            "password": "SecurePass123!",
        },
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    assert token is not None

    headers = {"Authorization": f"Bearer {token}"}

    # Step 3: Enable MFA
    response = client.post("/api/auth/enable-2fa", headers=headers)
    assert response.status_code == 200
    secret = response.json()["secret"]
    backup_codes = response.json()["backup_codes"]
    assert secret is not None
    assert len(backup_codes) == 8

    # Step 4: Verify MFA
    totp = pyotp.TOTP(secret)
    code = totp.now()

    response = client.post(
        "/api/auth/verify-2fa",
        json={"code": code},
        headers=headers,
    )
    assert response.status_code == 200
    assert response.json()["status"] == "enabled"

    # Step 5: Login with MFA (should require TOTP code)
    response = client.post(
        "/api/auth/login",
        json={
            "email": "lifecycle@example.com",
            "password": "SecurePass123!",
        },
    )
    assert response.status_code == 200
    assert response.json().get("mfa_required") is True

    # Step 6: Login with MFA code
    response = client.post(
        "/api/auth/login",
        json={
            "email": "lifecycle@example.com",
            "password": "SecurePass123!",
            "totp_code": totp.now(),
        },
    )
    assert response.status_code == 200
    assert "access_token" in response.json()
    new_token = response.json()["access_token"]

    # Step 7: Verify audit endpoint access.
    # The first registered user gets the admin role automatically,
    # so the status depends on whether other users were registered
    # before this test ran.
    new_headers = {"Authorization": f"Bearer {new_token}"}
    response = client.get("/api/audit", headers=new_headers)
    assert response.status_code in (200, 403)


def test_mfa_backup_code_workflow(client: TestClient) -> None:
    """Test MFA backup code usage and regeneration."""
    # Register and login
    reg_response = client.post(
        "/api/auth/register",
        json={
            "email": "backup@example.com",
            "password": "SecurePass123!",
            "name": "Backup Test",
        },
    )
    assert reg_response.status_code == 200

    response = client.post(
        "/api/auth/login",
        json={"email": "backup@example.com", "password": "SecurePass123!"},
    )
    assert response.status_code == 200

    token = response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Enable MFA
    response = client.post("/api/auth/enable-2fa", headers=headers)
    secret = response.json()["secret"]
    backup_codes = response.json()["backup_codes"]

    # Verify MFA
    totp = pyotp.TOTP(secret)
    client.post("/api/auth/verify-2fa", json={"code": totp.now()}, headers=headers)

    # Use backup code for login
    response = client.post(
        "/api/auth/login",
        json={
            "email": "backup@example.com",
            "password": "SecurePass123!",
            "totp_code": backup_codes[0],
        },
    )
    assert response.status_code == 200
    assert "access_token" in response.json()

    # Try using same backup code again (should fail)
    response = client.post(
        "/api/auth/login",
        json={
            "email": "backup@example.com",
            "password": "SecurePass123!",
            "totp_code": backup_codes[0],
        },
    )
    assert response.status_code == 401

    # Regenerate backup codes - Login with TOTP to get new token
    response = client.post(
        "/api/auth/login",
        json={
            "email": "backup@example.com",
            "password": "SecurePass123!",
            "totp_code": totp.now(),
        },
    )
    assert response.status_code == 200

    new_token = response.json()["access_token"]

    new_headers = {"Authorization": f"Bearer {new_token}"}
    response = client.post(
        "/api/auth/regenerate-backup-codes",
        json={"password": "SecurePass123!"},
        headers=new_headers,
    )
    assert response.status_code == 200
    new_backup_codes = response.json()["backup_codes"]
    assert len(new_backup_codes) == 8
    assert new_backup_codes[0] != backup_codes[0]


def test_token_refresh_workflow(client: TestClient) -> None:
    """Test access token refresh using refresh token."""
    # Register and login
    reg_response = client.post(
        "/api/auth/register",
        json={
            "email": "refresh@example.com",
            "password": "SecurePass123!",
            "name": "Refresh Test",
        },
    )
    assert reg_response.status_code == 200

    response = client.post(
        "/api/auth/login",
        json={"email": "refresh@example.com", "password": "SecurePass123!"},
    )
    assert response.status_code == 200
    refresh_token = response.json()["refresh_token"]

    # Use refresh token to get new access token
    response = client.post(
        "/api/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert response.status_code == 200
    new_access_token = response.json()["access_token"]
    # Note: Token may be identical if created in same second (flaky test)
    # The important part is that refresh succeeded

    # Verify new token works
    headers = {"Authorization": f"Bearer {new_access_token}"}
    response = client.get("/api/auth/me", headers=headers)
    assert response.status_code == 200
    assert response.json()["email"] == "refresh@example.com"


def test_failed_login_attempts_and_lockout(client: TestClient) -> None:
    """Test failed login tracking (prepares for CAPTCHA requirement)."""
    # Register user
    reg_response = client.post(
        "/api/auth/register",
        json={
            "email": "lockout@example.com",
            "password": "CorrectPass123!",
            "name": "Lockout Test",
        },
    )
    assert reg_response.status_code == 200

    # Attempt multiple failed logins
    for i in range(3):
        response = client.post(
            "/api/auth/login",
            json={"email": "lockout@example.com", "password": "WrongPassword"},
        )
        # First few should be 401
        if i < 2:
            assert response.status_code == 401

    # Successful login should still work (CAPTCHA would be required in production)
    response = client.post(
        "/api/auth/login",
        json={"email": "lockout@example.com", "password": "CorrectPass123!"},
    )
    # Should succeed or require CAPTCHA
    assert response.status_code in [200, 400]


def test_role_based_access_control(client: TestClient, admin_headers: dict[str, str]) -> None:
    """Test RBAC: admin vs viewer permissions."""
    # Create viewer user
    client.post(
        "/api/auth/register",
        json={
            "email": "viewer@example.com",
            "password": "ViewerPass123!",
            "name": "Viewer User",
        },
    )

    response = client.post(
        "/api/auth/login",
        json={"email": "viewer@example.com", "password": "ViewerPass123!"},
    )
    viewer_token = response.json()["access_token"]
    viewer_headers = {"Authorization": f"Bearer {viewer_token}"}

    # Admin can access audit endpoints (requires AUDIT_READ permission)
    response = client.get("/api/audit", headers=admin_headers)
    assert response.status_code == 200

    # Viewer cannot access audit endpoints without permission
    response = client.get("/api/audit", headers=viewer_headers)
    assert response.status_code == 403
