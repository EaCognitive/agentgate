"""Tests for server authentication endpoints."""

from fastapi.testclient import TestClient
from sqlmodel import Session

from tests.simple_auth_flow_support import login_user, register_and_login, register_user

pytest_plugins = ("tests.router_test_support",)

TEST_EMAIL = "test@example.com"
TEST_NAME = "Test User"
TEST_PASSWORD = "password123"


def test_register_user(client: TestClient):
    """Test user registration."""
    response = client.post(
        "/api/auth/register",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD, "name": TEST_NAME},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == TEST_EMAIL
    assert data["name"] == TEST_NAME
    assert data["role"] == "admin"  # First user is admin
    assert "hashed_password" not in data


def test_register_duplicate_email(client: TestClient):
    """Test registration with duplicate email fails."""
    register_user(client, email=TEST_EMAIL, password=TEST_PASSWORD, name=TEST_NAME)

    # Try to register again
    response = client.post(
        "/api/auth/register",
        json={
            "email": TEST_EMAIL,
            "password": "password456",
            "name": "Another User",
        },
    )
    assert response.status_code == 409
    assert "already registered" in response.json()["detail"]


def test_login_success(client: TestClient):
    """Test successful login."""
    register_user(client, email=TEST_EMAIL, password=TEST_PASSWORD, name=TEST_NAME)
    response = login_user(client, email=TEST_EMAIL, password=TEST_PASSWORD)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == 15 * 60  # 15 minutes in seconds
    assert data["user"]["email"] == TEST_EMAIL


def test_login_wrong_password(client: TestClient):
    """Test login with wrong password fails."""
    register_user(client, email=TEST_EMAIL, password=TEST_PASSWORD, name=TEST_NAME)
    response = login_user(client, email=TEST_EMAIL, password="wrongpassword")
    assert response.status_code == 401
    assert "Incorrect email or password" in response.json()["detail"]


def test_login_nonexistent_user(client: TestClient):
    """Test login with nonexistent user fails."""
    response = client.post(
        "/api/auth/login",
        json={
            "email": "nonexistent@example.com",
            "password": "password123",
        },
    )
    assert response.status_code == 401


def test_get_current_user(client: TestClient):
    """Test getting current user info."""
    token = register_and_login(client, email=TEST_EMAIL, password=TEST_PASSWORD, name=TEST_NAME)

    # Get current user
    response = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == TEST_EMAIL
    assert data["name"] == TEST_NAME


def test_get_current_user_unauthorized(client: TestClient):
    """Test getting current user without token fails."""
    response = client.get("/api/auth/me")
    assert response.status_code == 401


def test_refresh_token_success(client: TestClient):
    """Test refreshing access token."""
    register_user(client, email=TEST_EMAIL, password=TEST_PASSWORD, name=TEST_NAME)
    login_response = login_user(client, email=TEST_EMAIL, password=TEST_PASSWORD)
    refresh_token = login_response.json()["refresh_token"]

    # Refresh token
    response = client.post(
        "/api/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == 15 * 60


def test_refresh_token_invalid(client: TestClient):
    """Test refreshing with invalid token fails."""
    response = client.post(
        "/api/auth/refresh",
        json={"refresh_token": "invalid_token_here"},
    )
    assert response.status_code == 401
    assert "Invalid refresh token" in response.json()["detail"]


def test_revoke_refresh_token(client: TestClient, session: Session):
    """Test revoking refresh token."""
    _ = session
    register_user(client, email=TEST_EMAIL, password=TEST_PASSWORD, name=TEST_NAME)
    login_response = login_user(client, email=TEST_EMAIL, password=TEST_PASSWORD)
    access_token = login_response.json()["access_token"]
    refresh_token = login_response.json()["refresh_token"]

    # Revoke token
    response = client.post(
        "/api/auth/revoke",
        headers={"Authorization": f"Bearer {access_token}"},
        json={"refresh_token": refresh_token},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "revoked"

    # Try to use revoked token
    refresh_response = client.post(
        "/api/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert refresh_response.status_code == 401
    assert "revoked" in refresh_response.json()["detail"]


def test_second_user_is_viewer(client: TestClient):
    """Test that second registered user gets viewer role."""
    # First user (admin)
    client.post(
        "/api/auth/register",
        json={
            "email": "admin@example.com",
            "password": "password123",
            "name": "Admin User",
        },
    )

    # Second user (viewer)
    response = client.post(
        "/api/auth/register",
        json={
            "email": "viewer@example.com",
            "password": "password123",
            "name": "Viewer User",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["role"] == "viewer"
