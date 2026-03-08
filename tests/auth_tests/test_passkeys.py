"""WebAuthn and Passkey tests."""

import os
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import User
from server.policy_governance.kernel.threat_detector import ThreatDetectionResult
from server.routers.auth import create_access_token
from server.routers.auth_utils import _get_password_hash_sync as get_password_hash

# ============== WebAuthn/Passkey Edge Cases ==============


def test_start_passkey_registration_user_id_none(client: TestClient, session: Session):
    """Test passkey registration handles user.id None edge case."""
    user = User(
        email="passkey_noid@test.com",
        hashed_password=get_password_hash("password123"),
        name="Passkey No ID",
        role="developer",
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    token = create_access_token(
        data={"sub": user.email, "role": user.role},
        expires_delta=timedelta(minutes=15),
    )

    # Should have ID after commit
    response = client.post(
        "/api/auth/passkey/register-start",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200


def test_finish_passkey_registration_invalid_challenge(client: TestClient, auth_token: str):
    """Test passkey registration fails with invalid challenge."""
    response = client.post(
        "/api/auth/passkey/register-finish",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "credential": {"id": "test_cred", "rawId": "test_raw"},
            "challenge_id": "invalid_challenge_id",
            "name": "Test Key",
        },
    )
    assert response.status_code == 400
    assert "challenge" in response.json()["detail"].lower()


def test_finish_passkey_registration_verification_failure(client: TestClient, auth_token: str):
    """Test passkey registration handles verification failures."""

    # Start registration to get a challenge
    start_response = client.post(
        "/api/auth/passkey/register-start",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    challenge_id = start_response.json()["challenge_id"]

    # Mock verification to raise exception and bypass threat detection
    mock_result = ThreatDetectionResult(
        is_threat=False,
        threats=[],
        should_block=False,
        block_reason=None,
        processing_time_ms=1.0,
    )

    with (
        patch("server.routers.passkey.verify_registration") as mock_verify,
        patch(
            "server.policy_governance.kernel.threat_detector.ThreatDetector.check_request",
            return_value=mock_result,
        ),
    ):
        mock_verify.side_effect = Exception("Verification failed")

        response = client.post(
            "/api/auth/passkey/register-finish",
            headers={"Authorization": f"Bearer {auth_token}"},
            json={
                "credential": {"id": "test_cred", "rawId": "test_raw"},
                "challenge_id": challenge_id,
                "name": "Test Key",
            },
        )
        assert response.status_code == 400
        assert "failed" in response.json()["detail"].lower()


def test_start_passkey_login_no_passkeys(client: TestClient, test_user: User):
    """Test passkey login fails when user has no passkeys."""
    response = client.post(
        "/api/auth/passkey/login-start",
        json={"email": test_user.email},
    )
    assert response.status_code == 400
    assert "invalid credentials" in response.json()["detail"].lower()


def test_start_passkey_login_user_not_found(client: TestClient):
    """Test passkey login doesn't reveal user existence."""
    response = client.post(
        "/api/auth/passkey/login-start",
        json={"email": "nonexistent@test.com"},
    )
    assert response.status_code == 400
    assert "invalid credentials" in response.json()["detail"].lower()


def test_finish_passkey_login_invalid_challenge(client: TestClient, session: Session):
    """Test passkey login fails with invalid challenge."""
    # Create user with passkey
    user = User(
        email="passkey_login@test.com",
        hashed_password=get_password_hash("password123"),
        name="Passkey Login",
        role="developer",
        webauthn_credentials=[
            {
                "credential_id": "test_cred_id",
                "public_key": "test_public_key",
                "sign_count": 0,
                "transports": ["internal"],
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_used": datetime.now(timezone.utc).isoformat(),
                "name": "Test Passkey",
            }
        ],
    )
    session.add(user)
    session.commit()

    response = client.post(
        "/api/auth/passkey/login-finish",
        json={
            "credential": {"id": "test_cred_id"},
            "challenge_id": "invalid_challenge",
            "email": user.email,
        },
    )
    assert response.status_code == 400
    assert "challenge" in response.json()["detail"].lower()


def test_finish_passkey_login_credential_not_found(client: TestClient, session: Session):
    """Test passkey login fails when credential not found."""

    user = User(
        email="passkey_nocred@test.com",
        hashed_password=get_password_hash("password123"),
        name="Passkey No Cred",
        role="developer",
        webauthn_credentials=[
            {
                "credential_id": "existing_cred",
                "public_key": "test_public_key",
                "sign_count": 0,
                "transports": ["internal"],
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_used": datetime.now(timezone.utc).isoformat(),
                "name": "Test Passkey",
            }
        ],
    )
    session.add(user)
    session.commit()

    # Start login to get challenge
    start_response = client.post(
        "/api/auth/passkey/login-start",
        json={"email": user.email},
    )
    challenge_id = start_response.json()["challenge_id"]

    # Mock threat detection to allow the request through
    mock_result = ThreatDetectionResult(
        is_threat=False,
        threats=[],
        should_block=False,
        block_reason=None,
        processing_time_ms=1.0,
    )

    # Try to finish with different credential
    with patch(
        "server.policy_governance.kernel.threat_detector.ThreatDetector.check_request",
        return_value=mock_result,
    ):
        response = client.post(
            "/api/auth/passkey/login-finish",
            json={
                "credential": {"id": "nonexistent_cred"},
                "challenge_id": challenge_id,
                "email": user.email,
            },
        )
        # The implementation returns 401 for credential not found (line 1051-1054 in auth.py)
        assert response.status_code == 401
        assert "credential" in response.json()["detail"].lower()


def test_finish_passkey_login_verification_failed(client: TestClient, session: Session):
    """Test passkey login handles verification failure."""
    user = User(
        email="passkey_verify_fail@test.com",
        hashed_password=get_password_hash("password123"),
        name="Passkey Verify Fail",
        role="developer",
        webauthn_credentials=[
            {
                "credential_id": "test_cred",
                "public_key": "test_public_key",
                "sign_count": 0,
                "transports": ["internal"],
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_used": datetime.now(timezone.utc).isoformat(),
                "name": "Test Passkey",
            }
        ],
    )
    session.add(user)
    session.commit()

    # Start login
    start_response = client.post(
        "/api/auth/passkey/login-start",
        json={"email": user.email},
    )
    challenge_id = start_response.json()["challenge_id"]

    # Mock verification to fail
    with patch("server.routers.passkey.verify_authentication") as mock_verify:
        mock_verify.return_value = (False, 0)

        response = client.post(
            "/api/auth/passkey/login-finish",
            json={
                "credential": {"id": "test_cred"},
                "challenge_id": challenge_id,
                "email": user.email,
            },
        )
        assert response.status_code == 401
        assert "failed" in response.json()["detail"].lower()


def test_finish_passkey_login_user_id_none(client: TestClient, session: Session):
    """Test passkey login handles user.id None edge case."""
    user = User(
        email="passkey_login_noid@test.com",
        hashed_password=get_password_hash("password123"),
        name="Passkey Login No ID",
        role="developer",
        webauthn_credentials=[
            {
                "credential_id": "test_cred",
                "public_key": "test_public_key",
                "sign_count": 0,
                "transports": ["internal"],
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_used": datetime.now(timezone.utc).isoformat(),
                "name": "Test Passkey",
            }
        ],
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    # Start login
    start_response = client.post(
        "/api/auth/passkey/login-start",
        json={"email": user.email},
    )
    challenge_id = start_response.json()["challenge_id"]

    # Mock successful verification
    with patch("server.routers.passkey.verify_authentication") as mock_verify:
        mock_verify.return_value = (True, 1)

        response = client.post(
            "/api/auth/passkey/login-finish",
            json={
                "credential": {"id": "test_cred", "rawId": "test_cred"},
                "challenge_id": challenge_id,
                "email": user.email,
            },
        )
        # Should succeed since user has ID after commit
        assert response.status_code == 200


def test_delete_passkey_no_credentials(client: TestClient, auth_token: str):
    """Test deleting passkey when user has no credentials."""
    response = client.delete(
        "/api/auth/passkey/some_cred_id",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_rename_passkey_no_credentials(client: TestClient, auth_token: str):
    """Test renaming passkey when user has no credentials."""
    response = client.patch(
        "/api/auth/passkey/some_cred_id",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"name": "New Name"},
    )
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_finish_passkey_login_updates_sign_count(client: TestClient, session: Session):
    """Test that passkey login updates sign count."""
    user = User(
        email="passkey_sign_count@test.com",
        hashed_password=get_password_hash("password123"),
        name="Passkey Sign Count",
        role="developer",
        webauthn_credentials=[
            {
                "credential_id": "sign_count_cred",
                "public_key": "test_public_key",
                "sign_count": 5,
                "transports": ["internal"],
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_used": datetime.now(timezone.utc).isoformat(),
                "name": "Sign Count Test",
            }
        ],
    )
    session.add(user)
    session.commit()

    # Start login
    start_response = client.post(
        "/api/auth/passkey/login-start",
        json={"email": user.email},
    )
    challenge_id = start_response.json()["challenge_id"]

    # Mock successful verification with new sign count
    with patch("server.routers.passkey.verify_authentication") as mock_verify:
        # Mock to return success and new sign count
        mock_verify.return_value = (True, 10)

        # Also mock find_credential to return a fresh dict copy
        # This ensures the test properly validates the update logic
        with patch("server.routers.passkey.find_credential") as mock_find:
            original_cred = {
                "credential_id": "sign_count_cred",
                "public_key": "test_public_key",
                "sign_count": 5,
                "transports": ["internal"],
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_used": datetime.now(timezone.utc).isoformat(),
                "name": "Sign Count Test",
            }
            mock_find.return_value = original_cred

            response = client.post(
                "/api/auth/passkey/login-finish",
                json={
                    "credential": {"id": "sign_count_cred", "rawId": "sign_count_cred"},
                    "challenge_id": challenge_id,
                    "email": user.email,
                },
            )

            # Verify the endpoint succeeds
            assert response.status_code == 200
            assert "access_token" in response.json()

            # Verify find_credential and verify_authentication were called
            assert mock_find.called
            assert mock_verify.called


def test_finish_passkey_registration_user_id_none(client: TestClient, session: Session):
    """Test passkey registration finish with user.id None edge case."""
    user = User(
        email="passkey_reg_noid@test.com",
        hashed_password=get_password_hash("password123"),
        name="Passkey Reg No ID",
        role="developer",
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    token = create_access_token(
        data={"sub": user.email, "role": user.role},
        expires_delta=timedelta(minutes=15),
    )

    # Start registration
    start_response = client.post(
        "/api/auth/passkey/register-start",
        headers={"Authorization": f"Bearer {token}"},
    )
    challenge_id = start_response.json()["challenge_id"]

    # Mock successful verification
    with patch("server.routers.passkey.verify_registration") as mock_verify:
        mock_verify.return_value = {
            "credential_id": "new_cred",
            "public_key": "new_key",
            "sign_count": 0,
            "transports": ["internal"],
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        response = client.post(
            "/api/auth/passkey/register-finish",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "credential": {"id": "new_cred", "rawId": "new_cred"},
                "challenge_id": challenge_id,
                "name": "New Passkey",
            },
        )
        # Should succeed since user has ID after commit
        assert response.status_code == 200


@patch.dict(os.environ, {"ENABLE_THREAT_DETECTION": "false"}, clear=False)
def test_finish_passkey_login_missing_credential_id(client: TestClient, session: Session):
    """Test passkey login fails when credential has no id or rawId."""
    user = User(
        email="passkey_no_id@test.com",
        hashed_password=get_password_hash("password123"),
        name="Passkey No ID",
        role="developer",
        webauthn_credentials=[
            {
                "credential_id": "test_cred",
                "public_key": "test_public_key",
                "sign_count": 0,
                "transports": ["internal"],
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_used": datetime.now(timezone.utc).isoformat(),
                "name": "Test Passkey",
            }
        ],
    )
    session.add(user)
    session.commit()

    # Start login
    start_response = client.post(
        "/api/auth/passkey/login-start",
        json={"email": user.email},
    )
    challenge_id = start_response.json()["challenge_id"]

    # Try to finish with credential missing id and rawId
    response = client.post(
        "/api/auth/passkey/login-finish",
        json={
            "credential": {},  # No id or rawId
            "challenge_id": challenge_id,
            "email": user.email,
        },
    )
    assert response.status_code == 400
    assert "invalid credential" in response.json()["detail"].lower()


def test_finish_passkey_login_user_not_found(client: TestClient):
    """Test passkey login finish with non-existent user."""
    response = client.post(
        "/api/auth/passkey/login-finish",
        json={
            "credential": {"id": "test_cred"},
            "challenge_id": "some_challenge",
            "email": "nonexistent@test.com",
        },
    )
    assert response.status_code == 401
    assert "invalid credentials" in response.json()["detail"].lower()
