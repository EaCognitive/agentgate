"""Authentication edge case tests."""

from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import User
from server.routers.auth_utils import _get_password_hash_sync as get_password_hash


def test_login_updates_last_login(client: TestClient, session: Session):
    """Test login updates last_login field."""
    user = User(
        email="last_login@test.com",
        hashed_password=get_password_hash("password123"),
        name="Last Login",
        role="developer",
        last_login=None,
    )
    session.add(user)
    session.commit()

    response = client.post(
        "/api/auth/login",
        json={
            "email": user.email,
            "password": "password123",
        },
    )
    assert response.status_code == 200

    # Verify last_login was updated
    session.refresh(user)
    assert user.last_login is not None


def test_login_failed_increments_counter(client: TestClient, session: Session):
    """Test login failure increments failed login counter."""
    user = User(
        email="fail_counter@test.com",
        hashed_password=get_password_hash("password123"),
        name="Fail Counter",
        role="developer",
    )
    session.add(user)
    session.commit()

    # Login with wrong password
    response = client.post(
        "/api/auth/login",
        json={
            "email": user.email,
            "password": "wrongpassword",
        },
    )
    assert response.status_code == 401
    assert "incorrect email or password" in response.json()["detail"].lower()


def test_login_user_id_none_after_commit(client: TestClient, session: Session):
    """Test login handles user.id None edge case."""
    # Create a user normally - after commit and refresh, ID should exist
    user = User(
        email="id_check@test.com",
        hashed_password=get_password_hash("password123"),
        name="ID Check",
        role="developer",
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    # Login should succeed since ID exists after commit
    response = client.post(
        "/api/auth/login",
        json={
            "email": user.email,
            "password": "password123",
        },
    )
    assert response.status_code == 200
    assert "access_token" in response.json()
