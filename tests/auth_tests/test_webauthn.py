"""WebAuthn (Passkey) management tests."""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import User
from server.routers.auth import create_access_token
from server.routers.auth_utils import _get_password_hash_sync as get_password_hash


def test_list_passkeys_with_credentials(client: TestClient, session: Session):
    """Test listing passkeys."""
    user = User(
        email="list_passkeys@test.com",
        hashed_password=get_password_hash("password123"),
        name="List Passkeys",
        role="developer",
        webauthn_credentials=[
            {
                "credential_id": "cred1",
                "public_key": "key1",
                "sign_count": 5,
                "name": "My Passkey",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_used": datetime.now(timezone.utc).isoformat(),
                "transports": ["usb", "nfc"],
            },
            {
                "credential_id": "cred2",
                "public_key": "key2",
                "sign_count": 3,
                "name": "Another Key",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_used": datetime.now(timezone.utc).isoformat(),
                "transports": [],
            },
        ],
    )
    session.add(user)
    session.commit()

    token = create_access_token(
        data={"sub": user.email, "role": user.role},
        expires_delta=timedelta(minutes=15),
    )

    response = client.get(
        "/api/auth/passkey/list",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    assert data[0]["name"] == "My Passkey"
    assert data[0]["transports"] == ["usb", "nfc"]


def test_delete_passkey_success(client: TestClient, session: Session):
    """Test deleting a passkey."""
    user = User(
        email="delete_passkey@test.com",
        hashed_password=get_password_hash("password123"),
        name="Delete Passkey",
        role="developer",
        webauthn_credentials=[
            {
                "credential_id": "to_delete",
                "public_key": "key1",
                "sign_count": 1,
                "name": "Delete Me",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_used": datetime.now(timezone.utc).isoformat(),
                "transports": [],
            },
            {
                "credential_id": "keep_me",
                "public_key": "key2",
                "sign_count": 1,
                "name": "Keep Me",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_used": datetime.now(timezone.utc).isoformat(),
                "transports": [],
            },
        ],
    )
    session.add(user)
    session.commit()

    token = create_access_token(
        data={"sub": user.email, "role": user.role},
        expires_delta=timedelta(minutes=15),
    )

    response = client.delete(
        "/api/auth/passkey/to_delete",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "deleted"

    # Verify credential was deleted
    session.refresh(user)
    assert user.webauthn_credentials is not None
    assert len(user.webauthn_credentials) == 1
    assert user.webauthn_credentials[0]["credential_id"] == "keep_me"


def test_delete_passkey_not_found(client: TestClient, session: Session):
    """Test deleting non-existent passkey."""
    user = User(
        email="delete_notfound@test.com",
        hashed_password=get_password_hash("password123"),
        name="Delete Not Found",
        role="developer",
        webauthn_credentials=[
            {
                "credential_id": "existing",
                "public_key": "key1",
                "sign_count": 1,
                "name": "Existing",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_used": datetime.now(timezone.utc).isoformat(),
                "transports": [],
            },
        ],
    )
    session.add(user)
    session.commit()

    token = create_access_token(
        data={"sub": user.email, "role": user.role},
        expires_delta=timedelta(minutes=15),
    )

    response = client.delete(
        "/api/auth/passkey/nonexistent",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_rename_passkey_success(client: TestClient, session: Session):
    """Test renaming a passkey."""
    user = User(
        email="rename_passkey@test.com",
        hashed_password=get_password_hash("password123"),
        name="Rename Passkey",
        role="developer",
        webauthn_credentials=[
            {
                "credential_id": "to_rename",
                "public_key": "key1",
                "sign_count": 1,
                "name": "Old Name",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_used": datetime.now(timezone.utc).isoformat(),
                "transports": [],
            },
        ],
    )
    session.add(user)
    session.commit()

    token = create_access_token(
        data={"sub": user.email, "role": user.role},
        expires_delta=timedelta(minutes=15),
    )

    response = client.patch(
        "/api/auth/passkey/to_rename",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "New Name"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "updated"
    assert data["name"] == "New Name"

    # Verify name was changed
    session.refresh(user)
    assert user.webauthn_credentials is not None
    assert user.webauthn_credentials[0]["name"] == "New Name"


def test_rename_passkey_not_found(client: TestClient, session: Session):
    """Test renaming non-existent passkey."""
    user = User(
        email="rename_notfound@test.com",
        hashed_password=get_password_hash("password123"),
        name="Rename Not Found",
        role="developer",
        webauthn_credentials=[
            {
                "credential_id": "existing",
                "public_key": "key1",
                "sign_count": 1,
                "name": "Existing",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_used": datetime.now(timezone.utc).isoformat(),
                "transports": [],
            },
        ],
    )
    session.add(user)
    session.commit()

    token = create_access_token(
        data={"sub": user.email, "role": user.role},
        expires_delta=timedelta(minutes=15),
    )

    response = client.patch(
        "/api/auth/passkey/nonexistent",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "New Name"},
    )
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_passkey_registration_user_id_check(client: TestClient, session: Session):
    """Test passkey registration validates user ID."""
    user = User(
        email="passkey_id@test.com",
        hashed_password=get_password_hash("password123"),
        name="Passkey ID",
        role="developer",
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    token = create_access_token(
        data={"sub": user.email, "role": user.role},
        expires_delta=timedelta(minutes=15),
    )

    # Start registration - should succeed since user has ID
    response = client.post(
        "/api/auth/passkey/register-start",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert "challenge_id" in response.json()


@patch("server.routers.passkey.verify_registration")
def test_passkey_registration_finish_user_id_check(
    mock_verify_reg,
    client: TestClient,
    session: Session,
):
    """Test passkey registration finish validates user ID."""
    user = User(
        email="passkey_fin_id@test.com",
        hashed_password=get_password_hash("password123"),
        name="Passkey Fin ID",
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
    mock_verify_reg.return_value = {
        "credential_id": "test_cred",
        "public_key": "test_key",
        "sign_count": 0,
        "transports": [],
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    # Finish registration - should succeed
    response = client.post(
        "/api/auth/passkey/register-finish",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "credential": {"id": "test_cred", "rawId": "test_cred"},
            "challenge_id": challenge_id,
            "name": "Test Key",
        },
    )
    assert response.status_code == 200


@patch("server.routers.passkey.verify_authentication")
def test_passkey_login_finish_user_id_check(
    mock_verify_auth,
    client: TestClient,
    session: Session,
):
    """Test passkey login finish validates user ID."""
    user = User(
        email="passkey_login_id@test.com",
        hashed_password=get_password_hash("password123"),
        name="Passkey Login ID",
        role="developer",
        webauthn_credentials=[
            {
                "credential_id": "test_cred",
                "public_key": "test_key",
                "sign_count": 0,
                "name": "Test Key",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_used": datetime.now(timezone.utc).isoformat(),
                "transports": [],
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
    mock_verify_auth.return_value = (True, 1)

    # Finish login - should succeed
    response = client.post(
        "/api/auth/passkey/login-finish",
        json={
            "credential": {"id": "test_cred", "rawId": "test_cred"},
            "challenge_id": challenge_id,
            "email": user.email,
        },
    )
    assert response.status_code == 200
    assert "access_token" in response.json()
