"""Tests for WebAuthn/Passkey authentication endpoints.

These tests verify the API endpoints for passwordless authentication.
"""

import os
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import User
from tests.router_test_support import bearer_token, create_test_user

os.environ["REDIS_URL"] = "memory://"

pytest_plugins = ("tests.router_test_support",)


@pytest.fixture(name="passkey_user")
def _passkey_user_impl(session: Session) -> User:
    """Create a test user for authentication."""
    return create_test_user(
        session,
        email="passkey@test.com",
        name="Passkey Test User",
        password="testpassword123",
        role="developer",
        is_active=True,
        webauthn_credentials=[],
    )


@pytest.fixture(name="auth_token")
def _auth_token_impl(passkey_user: User) -> str:
    """Create an authentication token for the test user."""
    return bearer_token(passkey_user, expires_delta=timedelta(minutes=15))


def test_list_passkeys_empty(client: TestClient, passkey_user: User, auth_token: str):
    """Test listing passkeys when user has none registered."""
    _ = passkey_user
    response = client.get(
        "/api/auth/passkey/list",
        headers={"Authorization": f"Bearer {auth_token}"},
    )

    assert response.status_code == 200
    assert not response.json()


def test_list_passkeys_with_credentials(
    client: TestClient, session: Session, passkey_user: User, auth_token: str
):
    """Test listing passkeys when user has registered credentials."""
    _ = passkey_user
    # Add a mock credential to the user
    passkey_user.webauthn_credentials = [
        {
            "credential_id": "test_credential_id_base64",
            "public_key": "test_public_key_base64",
            "sign_count": 0,
            "transports": ["internal"],
            "created_at": "2025-01-28T10:00:00Z",
            "last_used": "2025-01-28T10:00:00Z",
            "name": "Test Passkey",
        }
    ]
    session.add(passkey_user)
    session.commit()

    response = client.get(
        "/api/auth/passkey/list",
        headers={"Authorization": f"Bearer {auth_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["name"] == "Test Passkey"
    assert data[0]["credential_id"] == "test_credential_id_base64"
    assert data[0]["transports"] == ["internal"]
    assert "public_key" not in data[0]  # Should not expose public key
    assert "sign_count" not in data[0]  # Should not expose sign count


def test_list_passkeys_unauthenticated(client: TestClient):
    """Test that listing passkeys requires authentication."""
    response = client.get("/api/auth/passkey/list")

    assert response.status_code == 401
    assert "not authenticated" in response.json()["detail"].lower()


def test_start_passkey_registration(client: TestClient, passkey_user: User, auth_token: str):
    """Test starting passkey registration process."""
    _ = passkey_user
    response = client.post(
        "/api/auth/passkey/register-start",
        headers={"Authorization": f"Bearer {auth_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert "options" in data
    assert "challenge_id" in data
    assert data["challenge_id"]  # Should not be empty

    # Verify options structure
    options = data["options"]
    assert "challenge" in options
    assert "rp" in options
    assert "user" in options
    assert options["user"]["name"] == passkey_user.email


def test_start_passkey_registration_unauthenticated(client: TestClient):
    """Test that starting registration requires authentication."""
    response = client.post("/api/auth/passkey/register-start")

    assert response.status_code == 401


def test_delete_passkey(client: TestClient, session: Session, passkey_user: User, auth_token: str):
    """Test deleting a passkey."""
    _ = passkey_user
    # Add a credential to delete
    credential_id = "test_credential_to_delete"
    passkey_user.webauthn_credentials = [
        {
            "credential_id": credential_id,
            "public_key": "test_public_key",
            "sign_count": 0,
            "transports": ["internal"],
            "created_at": "2025-01-28T10:00:00Z",
            "last_used": "2025-01-28T10:00:00Z",
            "name": "To Delete",
        }
    ]
    session.add(passkey_user)
    session.commit()

    # Delete the credential
    response = client.delete(
        f"/api/auth/passkey/{credential_id}",
        headers={"Authorization": f"Bearer {auth_token}"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "deleted"

    # Verify it was deleted
    session.refresh(passkey_user)
    assert not passkey_user.webauthn_credentials


def test_delete_nonexistent_passkey(client: TestClient, passkey_user: User, auth_token: str):
    """Test deleting a passkey that doesn't exist."""
    _ = passkey_user
    response = client.delete(
        "/api/auth/passkey/nonexistent_id",
        headers={"Authorization": f"Bearer {auth_token}"},
    )

    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_rename_passkey(client: TestClient, session: Session, passkey_user: User, auth_token: str):
    """Test renaming a passkey."""
    _ = passkey_user
    # Add a credential to rename
    credential_id = "test_credential_to_rename"
    passkey_user.webauthn_credentials = [
        {
            "credential_id": credential_id,
            "public_key": "test_public_key",
            "sign_count": 0,
            "transports": ["internal"],
            "created_at": "2025-01-28T10:00:00Z",
            "last_used": "2025-01-28T10:00:00Z",
            "name": "Old Name",
        }
    ]
    session.add(passkey_user)
    session.commit()

    # Rename the credential
    new_name = "New Name"
    response = client.patch(
        f"/api/auth/passkey/{credential_id}",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"name": new_name},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "updated"
    assert response.json()["name"] == new_name

    # Verify it was renamed
    session.refresh(passkey_user)
    assert passkey_user.webauthn_credentials[0]["name"] == new_name


def test_rename_nonexistent_passkey(client: TestClient, passkey_user: User, auth_token: str):
    """Test renaming a passkey that doesn't exist."""
    _ = passkey_user
    response = client.patch(
        "/api/auth/passkey/nonexistent_id",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"name": "New Name"},
    )

    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_passkey_authentication_flow_start(
    client: TestClient, session: Session, passkey_user: User
):
    """Test starting passkey authentication flow."""
    _ = passkey_user
    # Add a credential for the user
    passkey_user.webauthn_credentials = [
        {
            "credential_id": "test_credential_id",
            "public_key": "test_public_key",
            "sign_count": 0,
            "transports": ["internal"],
            "created_at": "2025-01-28T10:00:00Z",
            "last_used": "2025-01-28T10:00:00Z",
            "name": "Test Passkey",
        }
    ]
    session.add(passkey_user)
    session.commit()

    # Start authentication
    response = client.post(
        "/api/auth/passkey/login-start",
        json={"email": passkey_user.email},
    )

    assert response.status_code == 200
    data = response.json()
    assert "options" in data
    assert "challenge_id" in data

    # Verify options structure
    options = data["options"]
    assert "challenge" in options
    assert "allowCredentials" in options


def test_passkey_authentication_no_credentials(client: TestClient, passkey_user: User):
    """Test that authentication fails when user has no passkeys."""
    _ = passkey_user
    response = client.post(
        "/api/auth/passkey/login-start",
        json={"email": passkey_user.email},
    )

    assert response.status_code == 400
    assert "invalid credentials" in response.json()["detail"].lower()


def test_passkey_authentication_invalid_email(client: TestClient):
    """Test that authentication fails with invalid email."""
    response = client.post(
        "/api/auth/passkey/login-start",
        json={"email": "nonexistent@test.com"},
    )

    assert response.status_code == 400
    # Should not reveal if user exists
    assert "invalid credentials" in response.json()["detail"].lower()
