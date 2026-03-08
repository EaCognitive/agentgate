"""Registration flow tests."""

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from server.models import User
from server.routers.auth_utils import _get_password_hash_sync as get_password_hash


def test_register_new_user_as_admin(client: TestClient, session: Session):
    """Test first user registration becomes admin."""
    # Ensure no users exist
    assert session.exec(select(User)).first() is None

    response = client.post(
        "/api/auth/register",
        json={
            "email": "first@test.com",
            "password": "password123",
            "name": "First User",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "first@test.com"
    assert data["role"] == "admin"


def test_register_subsequent_user_as_viewer(client: TestClient, session: Session):
    """Test subsequent user registration becomes viewer."""
    # Create first user (admin)
    first_user = User(
        email="admin@test.com",
        hashed_password=get_password_hash("password123"),
        name="Admin",
        role="admin",
    )
    session.add(first_user)
    session.commit()

    response = client.post(
        "/api/auth/register",
        json={
            "email": "second@test.com",
            "password": "password123",
            "name": "Second User",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "second@test.com"
    assert data["role"] == "viewer"


def test_register_duplicate_email(client: TestClient, test_user: User):
    """Test registration fails with duplicate email."""
    response = client.post(
        "/api/auth/register",
        json={
            "email": test_user.email,
            "password": "password123",
            "name": "Duplicate",
        },
    )
    assert response.status_code == 409
    assert "already registered" in response.json()["detail"].lower()
