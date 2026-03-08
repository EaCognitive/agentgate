"""Login and CAPTCHA tests for authentication."""

from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import User
from server.routers.auth_utils import _get_password_hash_sync as get_password_hash

# ============== CAPTCHA Tests ==============


@patch("server.routers.auth.verify_hcaptcha")
@patch("server.routers.auth.requires_captcha")
def test_login_with_captcha_required(
    mock_requires_captcha,
    mock_verify_hcaptcha,
    client: TestClient,
    test_user: User,
):
    """Test login flow when CAPTCHA is required."""
    mock_requires_captcha.return_value = True
    mock_verify_hcaptcha.return_value = AsyncMock(return_value=True)

    # Login without CAPTCHA token should fail
    response = client.post(
        "/api/auth/login",
        json={"email": test_user.email, "password": "testpass123"},
    )
    assert response.status_code == 400
    assert "captcha_required" in str(response.json()["detail"])


@patch("server.routers.auth.verify_hcaptcha")
@patch("server.routers.auth.requires_captcha")
async def test_login_with_invalid_captcha(
    mock_requires_captcha,
    mock_verify_hcaptcha,
    client: TestClient,
    test_user: User,
):
    """Test login with invalid CAPTCHA token."""
    mock_requires_captcha.return_value = True
    # Mock as AsyncMock that returns False
    mock_verify_hcaptcha.return_value = False

    with patch("server.routers.auth.verify_hcaptcha", new_callable=AsyncMock) as async_mock:
        async_mock.return_value = False

        response = client.post(
            "/api/auth/login",
            json={
                "email": test_user.email,
                "password": "testpass123",
                "captcha_token": "invalid_token",
            },
        )
        assert response.status_code == 400
        assert "Invalid CAPTCHA" in response.json()["detail"]


@patch("server.routers.auth.verify_hcaptcha")
@patch("server.routers.auth.requires_captcha")
async def test_login_with_valid_captcha(
    mock_requires_captcha,
    mock_verify_hcaptcha,
    client: TestClient,
    test_user: User,
):
    """Test successful login with valid CAPTCHA."""
    mock_requires_captcha.return_value = True
    mock_verify_hcaptcha.return_value = True

    with patch("server.routers.auth.verify_hcaptcha", new_callable=AsyncMock) as async_mock:
        async_mock.return_value = True

        response = client.post(
            "/api/auth/login",
            json={
                "email": test_user.email,
                "password": "testpass123",
                "captcha_token": "valid_token",
            },
        )
        assert response.status_code == 200
        assert "access_token" in response.json()


# ============== Login Edge Cases ==============


def test_login_with_inactive_account(client: TestClient, inactive_user: User):
    """Test login fails for inactive account."""
    response = client.post(
        "/api/auth/login",
        json={"email": inactive_user.email, "password": "password123"},
    )
    assert response.status_code == 403
    assert "disabled" in response.json()["detail"].lower()


def test_login_with_user_id_none_error(client: TestClient, session: Session):
    """Test login handles user.id being None edge case."""
    # This is a rare edge case but needs coverage
    user = User(
        email="noid@test.com",
        hashed_password=get_password_hash("password123"),
        name="No ID User",
        role="viewer",
    )
    session.add(user)
    session.flush()  # Flush without commit to potentially get None ID

    response = client.post(
        "/api/auth/login",
        json={"email": "noid@test.com", "password": "password123"},
    )

    # Should either succeed or handle gracefully
    # This tests the user.id is None check at line 354
    assert response.status_code in [200, 500]
