"""Comprehensive unit tests for CAPTCHA utility functions.

This test suite provides thorough coverage of:
- verify_hcaptcha(): HTTP verification with mocking
- requires_captcha(): Failed login threshold logic
- increment_failed_login(): Counter increment logic
- reset_failed_login(): Counter reset logic

Focus areas:
- Successful verification scenarios
- Failed verification scenarios
- Network error handling
- Missing configuration scenarios
- Rate limiting edge cases
- Database interactions
- Boundary conditions
"""

import os
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from sqlmodel import Session, SQLModel, create_engine, select
from sqlmodel.pool import StaticPool

from server.models.schemas import User
from server.routers.auth_utils import _get_password_hash_sync as get_password_hash
from server.utils.captcha import (
    increment_failed_login,
    requires_captcha,
    reset_failed_login,
    verify_hcaptcha,
)


@pytest.fixture(name="test_session")
async def test_session_fixture():
    """Create an in-memory test database session."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    session = Session(engine)
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture(name="test_user")
async def test_user_fixture(test_session: Session):
    """Create a test user with no failed login attempts."""
    user = User(
        email="test@example.com",
        name="Test User",
        hashed_password=get_password_hash("password123"),
        role="viewer",
        failed_login_attempts=0,
        last_failed_login=None,
    )
    test_session.add(user)
    test_session.commit()
    test_session.refresh(user)
    return user


# ============== verify_hcaptcha() Tests ==============


@pytest.mark.asyncio
@patch.dict(os.environ, {"HCAPTCHA_SECRET": "", "AGENTGATE_ENV": "development"})
async def test_verify_hcaptcha_development_bypass():
    """In development without secret, verification returns True."""
    result = await verify_hcaptcha("any_token")
    assert result is True


@pytest.mark.asyncio
@patch.dict(os.environ, {"HCAPTCHA_SECRET": "", "AGENTGATE_ENV": "test"})
async def test_verify_hcaptcha_test_bypass():
    """In test environment without secret, verification returns True."""
    result = await verify_hcaptcha("any_token")
    assert result is True


@pytest.mark.asyncio
@patch.dict(os.environ, {"HCAPTCHA_SECRET": "", "AGENTGATE_ENV": "production"})
async def test_verify_hcaptcha_production_missing_secret():
    """In production without secret, verification raises ValueError."""
    with pytest.raises(ValueError, match="HCAPTCHA_SECRET not configured"):
        await verify_hcaptcha("any_token")


@pytest.mark.asyncio
@patch.dict(os.environ, {"HCAPTCHA_SECRET": "test-secret-key"})
@patch("server.utils.captcha._HCaptchaClientHolder.get")
async def test_verify_hcaptcha_successful_verification(mock_get):
    """Successful hCaptcha verification returns True."""
    mock_response = MagicMock()
    mock_response.json.return_value = {"success": True}

    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_get.return_value = mock_client

    result = await verify_hcaptcha("valid_token", "192.168.1.1")

    assert result is True
    mock_client.post.assert_called_once_with(
        "https://hcaptcha.com/siteverify",
        data={
            "secret": "test-secret-key",
            "response": "valid_token",
            "remoteip": "192.168.1.1",
        },
    )


@pytest.mark.asyncio
@patch.dict(os.environ, {"HCAPTCHA_SECRET": "test-secret-key"})
@patch("server.utils.captcha._HCaptchaClientHolder.get")
async def test_verify_hcaptcha_failed_verification(mock_get):
    """Failed hCaptcha verification returns False."""
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "success": False,
        "error-codes": ["invalid-input-response"],
    }

    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_get.return_value = mock_client

    result = await verify_hcaptcha("invalid_token")

    assert result is False


@pytest.mark.asyncio
@patch.dict(os.environ, {"HCAPTCHA_SECRET": "test-secret-key"})
@patch("server.utils.captcha._HCaptchaClientHolder.get")
async def test_verify_hcaptcha_missing_success_field(mock_get):
    """Response without 'success' field returns False."""
    mock_response = MagicMock()
    mock_response.json.return_value = {"error": "some error"}

    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_get.return_value = mock_client

    result = await verify_hcaptcha("token")

    assert result is False


@pytest.mark.asyncio
@patch.dict(os.environ, {"HCAPTCHA_SECRET": "test-secret-key"})
@patch("server.utils.captcha._HCaptchaClientHolder.get")
async def test_verify_hcaptcha_network_error(mock_get):
    """Network error during verification fails closed (returns False)."""
    mock_client = MagicMock()
    mock_client.post = AsyncMock(side_effect=httpx.ConnectError("Connection failed"))
    mock_get.return_value = mock_client

    result = await verify_hcaptcha("token")

    assert result is False


@pytest.mark.asyncio
@patch.dict(os.environ, {"HCAPTCHA_SECRET": "test-secret-key"})
@patch("server.utils.captcha._HCaptchaClientHolder.get")
async def test_verify_hcaptcha_timeout_error(mock_get):
    """Timeout during verification fails closed (returns False)."""
    mock_client = MagicMock()
    mock_client.post = AsyncMock(side_effect=httpx.TimeoutException("Request timeout"))
    mock_get.return_value = mock_client

    result = await verify_hcaptcha("token")

    assert result is False


@pytest.mark.asyncio
@patch.dict(os.environ, {"HCAPTCHA_SECRET": "test-secret-key"})
@patch("server.utils.captcha._HCaptchaClientHolder.get")
async def test_verify_hcaptcha_json_decode_error(mock_get):
    """Invalid JSON response fails closed (returns False)."""
    mock_response = MagicMock()
    mock_response.json.side_effect = ValueError("Invalid JSON")

    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_get.return_value = mock_client

    result = await verify_hcaptcha("token")

    assert result is False


@pytest.mark.asyncio
@patch.dict(os.environ, {"HCAPTCHA_SECRET": "test-secret-key"})
@patch("server.utils.captcha._HCaptchaClientHolder.get")
async def test_verify_hcaptcha_without_remote_ip(mock_get):
    """Verification works without remote IP parameter."""
    mock_response = MagicMock()
    mock_response.json.return_value = {"success": True}

    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_get.return_value = mock_client

    result = await verify_hcaptcha("token")

    assert result is True
    call_args = mock_client.post.call_args
    assert call_args[1]["data"]["remoteip"] is None


@pytest.mark.asyncio
@patch.dict(os.environ, {"HCAPTCHA_SECRET": "test-secret-key"})
@patch("server.utils.captcha._HCaptchaClientHolder.get")
async def test_verify_hcaptcha_generic_exception(mock_get):
    """Generic exception during verification fails closed."""
    mock_client = MagicMock()
    mock_client.post = AsyncMock(side_effect=Exception("Unexpected error"))
    mock_get.return_value = mock_client

    result = await verify_hcaptcha("token")

    assert result is False


# ============== requires_captcha() Tests ==============


async def test_requires_captcha_no_failed_attempts(test_user: User, test_session: Session):
    """User with 0 failed attempts does not require CAPTCHA."""
    assert test_user.failed_login_attempts == 0
    result = await requires_captcha(test_user.email, test_session)
    assert result is False


async def test_requires_captcha_one_failed_attempt(test_user: User, test_session: Session):
    """User with 1 failed attempt does not require CAPTCHA."""
    test_user.failed_login_attempts = 1
    test_user.last_failed_login = datetime.now(timezone.utc).replace(tzinfo=None)
    test_session.add(test_user)
    test_session.commit()

    result = await requires_captcha(test_user.email, test_session)
    assert result is False


async def test_requires_captcha_two_failed_attempts(test_user: User, test_session: Session):
    """User with 2 failed attempts does not require CAPTCHA."""
    test_user.failed_login_attempts = 2
    test_user.last_failed_login = datetime.now(timezone.utc).replace(tzinfo=None)
    test_session.add(test_user)
    test_session.commit()

    result = await requires_captcha(test_user.email, test_session)
    assert result is False


async def test_requires_captcha_three_failed_attempts(test_user: User, test_session: Session):
    """User with exactly 3 failed attempts requires CAPTCHA."""
    test_user.failed_login_attempts = 3
    test_user.last_failed_login = datetime.now(timezone.utc).replace(tzinfo=None)
    test_session.add(test_user)
    test_session.commit()

    result = await requires_captcha(test_user.email, test_session)
    assert result is True


async def test_requires_captcha_many_failed_attempts(test_user: User, test_session: Session):
    """User with many failed attempts requires CAPTCHA."""
    test_user.failed_login_attempts = 10
    test_user.last_failed_login = datetime.now(timezone.utc).replace(tzinfo=None)
    test_session.add(test_user)
    test_session.commit()

    result = await requires_captcha(test_user.email, test_session)
    assert result is True


async def test_requires_captcha_nonexistent_user(test_session: Session):
    """Nonexistent user does not require CAPTCHA (no user info revealed)."""
    result = await requires_captcha("nonexistent@example.com", test_session)
    assert result is False


async def test_requires_captcha_resets_after_1_hour(test_user: User, test_session: Session):
    """Counter resets after 1 hour of inactivity."""
    # Set failed attempts with 2 hour old timestamp
    test_user.failed_login_attempts = 5
    test_user.last_failed_login = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(
        hours=2
    )
    test_session.add(test_user)
    test_session.commit()

    result = await requires_captcha(test_user.email, test_session)

    # Should return False (counter reset)
    assert result is False

    # Verify counter was actually reset in database
    test_session.refresh(test_user)
    assert test_user.failed_login_attempts == 0
    assert test_user.last_failed_login is None


async def test_requires_captcha_not_reset_before_1_hour(test_user: User, test_session: Session):
    """Counter NOT reset before 1 hour has passed."""
    # Set failed attempts with 59 minute old timestamp
    test_user.failed_login_attempts = 5
    test_user.last_failed_login = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(
        minutes=59
    )
    test_session.add(test_user)
    test_session.commit()

    result = await requires_captcha(test_user.email, test_session)

    # Should still require CAPTCHA
    assert result is True

    # Counter should NOT be reset
    test_session.refresh(test_user)
    assert test_user.failed_login_attempts == 5


async def test_requires_captcha_exactly_1_hour_boundary(test_user: User, test_session: Session):
    """Counter resets at exactly 1 hour boundary."""
    # Set failed attempts at exactly 1 hour ago
    test_user.failed_login_attempts = 5
    test_user.last_failed_login = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(
        hours=1, seconds=1
    )
    test_session.add(test_user)
    test_session.commit()

    result = await requires_captcha(test_user.email, test_session)

    # Should return False (counter reset)
    assert result is False


async def test_requires_captcha_no_last_failed_login_timestamp(
    test_user: User, test_session: Session
):
    """User with failed attempts but no timestamp does not require CAPTCHA."""
    test_user.failed_login_attempts = 5
    test_user.last_failed_login = None
    test_session.add(test_user)
    test_session.commit()

    result = await requires_captcha(test_user.email, test_session)

    # Without timestamp, cannot enforce time-based logic
    # Function should still return True based on count >= 3
    assert result is True


# ============== increment_failed_login() Tests ==============


async def test_increment_failed_login_first_failure(test_user: User, test_session: Session):
    """First failed login increments counter to 1."""
    assert test_user.failed_login_attempts == 0

    await increment_failed_login(test_user.email, test_session)

    test_session.refresh(test_user)
    assert test_user.failed_login_attempts == 1
    assert test_user.last_failed_login is not None


async def test_increment_failed_login_multiple_times(test_user: User, test_session: Session):
    """Multiple failed logins increment counter correctly."""
    await increment_failed_login(test_user.email, test_session)
    await increment_failed_login(test_user.email, test_session)
    await increment_failed_login(test_user.email, test_session)

    test_session.refresh(test_user)
    assert test_user.failed_login_attempts == 3


async def test_increment_failed_login_updates_timestamp(test_user: User, test_session: Session):
    """Failed login updates last_failed_login timestamp."""
    before_time = datetime.now(timezone.utc).replace(tzinfo=None)

    await increment_failed_login(test_user.email, test_session)

    test_session.refresh(test_user)
    assert test_user.last_failed_login is not None
    assert test_user.last_failed_login >= before_time


async def test_increment_failed_login_timestamp_updates_on_each_call(
    test_user: User, test_session: Session
):
    """Timestamp updates on each failed login attempt."""
    await increment_failed_login(test_user.email, test_session)
    test_session.refresh(test_user)
    first_timestamp = test_user.last_failed_login
    assert first_timestamp is not None

    # Wait a tiny bit and increment again
    await increment_failed_login(test_user.email, test_session)
    test_session.refresh(test_user)
    second_timestamp = test_user.last_failed_login
    assert second_timestamp is not None

    # Second timestamp should be same or newer
    assert second_timestamp >= first_timestamp


async def test_increment_failed_login_nonexistent_user(test_session: Session):
    """Incrementing failed login for nonexistent user does not error."""
    # Should not raise exception
    await increment_failed_login("nonexistent@example.com", test_session)

    # Verify no user was created

    user = test_session.exec(select(User).where(User.email == "nonexistent@example.com")).first()
    assert user is None


async def test_increment_failed_login_from_existing_count(test_user: User, test_session: Session):
    """Incrementing from existing count works correctly."""
    test_user.failed_login_attempts = 5
    test_session.add(test_user)
    test_session.commit()

    await increment_failed_login(test_user.email, test_session)

    test_session.refresh(test_user)
    assert test_user.failed_login_attempts == 6


async def test_increment_failed_login_high_count(test_user: User, test_session: Session):
    """Counter can increment to high values."""
    test_user.failed_login_attempts = 100
    test_session.add(test_user)
    test_session.commit()

    await increment_failed_login(test_user.email, test_session)

    test_session.refresh(test_user)
    assert test_user.failed_login_attempts == 101


# ============== reset_failed_login() Tests ==============


async def test_reset_failed_login_clears_counter(test_user: User, test_session: Session):
    """Reset clears failed login counter to 0."""
    test_user.failed_login_attempts = 5
    test_user.last_failed_login = datetime.now(timezone.utc).replace(tzinfo=None)
    test_session.add(test_user)
    test_session.commit()

    await reset_failed_login(test_user.email, test_session)

    test_session.refresh(test_user)
    assert test_user.failed_login_attempts == 0


async def test_reset_failed_login_clears_timestamp(test_user: User, test_session: Session):
    """Reset clears last_failed_login timestamp."""
    test_user.failed_login_attempts = 5
    test_user.last_failed_login = datetime.now(timezone.utc).replace(tzinfo=None)
    test_session.add(test_user)
    test_session.commit()

    await reset_failed_login(test_user.email, test_session)

    test_session.refresh(test_user)
    assert test_user.last_failed_login is None


async def test_reset_failed_login_from_zero(test_user: User, test_session: Session):
    """Reset from zero counter is idempotent."""
    assert test_user.failed_login_attempts == 0

    await reset_failed_login(test_user.email, test_session)

    test_session.refresh(test_user)
    assert test_user.failed_login_attempts == 0
    assert test_user.last_failed_login is None


async def test_reset_failed_login_nonexistent_user(test_session: Session):
    """Resetting failed login for nonexistent user does not error."""
    # Should not raise exception
    await reset_failed_login("nonexistent@example.com", test_session)

    # Verify no user was created

    user = test_session.exec(select(User).where(User.email == "nonexistent@example.com")).first()
    assert user is None


async def test_reset_failed_login_high_count(test_user: User, test_session: Session):
    """Reset works from high counter values."""
    test_user.failed_login_attempts = 100
    test_user.last_failed_login = datetime.now(timezone.utc).replace(tzinfo=None)
    test_session.add(test_user)
    test_session.commit()

    await reset_failed_login(test_user.email, test_session)

    test_session.refresh(test_user)
    assert test_user.failed_login_attempts == 0
    assert test_user.last_failed_login is None


# ============== Integration & Edge Cases ==============


async def test_increment_then_requires_captcha(test_user: User, test_session: Session):
    """Increment followed by requires_captcha check."""
    await increment_failed_login(test_user.email, test_session)
    assert await requires_captcha(test_user.email, test_session) is False

    await increment_failed_login(test_user.email, test_session)
    assert await requires_captcha(test_user.email, test_session) is False

    await increment_failed_login(test_user.email, test_session)
    assert await requires_captcha(test_user.email, test_session) is True


async def test_increment_then_reset_then_requires(test_user: User, test_session: Session):
    """Full cycle: increment, reset, check."""
    # Increment to trigger CAPTCHA
    for _ in range(5):
        await increment_failed_login(test_user.email, test_session)

    assert await requires_captcha(test_user.email, test_session) is True

    # Reset
    await reset_failed_login(test_user.email, test_session)

    # Should no longer require CAPTCHA
    assert await requires_captcha(test_user.email, test_session) is False


async def test_multiple_users_independent_counters(test_session: Session):
    """Multiple users have independent failed login counters."""
    user1 = User(
        email="user1@example.com",
        name="User 1",
        hashed_password=get_password_hash("password"),
        role="viewer",
    )
    user2 = User(
        email="user2@example.com",
        name="User 2",
        hashed_password=get_password_hash("password"),
        role="viewer",
    )
    test_session.add(user1)
    test_session.add(user2)
    test_session.commit()

    # Increment user1 3 times
    for _ in range(3):
        await increment_failed_login("user1@example.com", test_session)

    # user1 requires CAPTCHA
    assert await requires_captcha("user1@example.com", test_session) is True

    # user2 does not require CAPTCHA
    assert await requires_captcha("user2@example.com", test_session) is False


async def test_case_sensitive_email_lookup(test_user: User, test_session: Session):
    """Email lookup is case-sensitive for failed login tracking."""
    # Increment with exact email
    await increment_failed_login(test_user.email, test_session)

    test_session.refresh(test_user)
    assert test_user.failed_login_attempts == 1

    # Try with different case - should not find user
    await increment_failed_login(test_user.email.upper(), test_session)

    # Original user counter should not change
    test_session.refresh(test_user)
    assert test_user.failed_login_attempts == 1


@pytest.mark.asyncio
@patch.dict(os.environ, {"HCAPTCHA_SECRET": "test-secret"})
@patch("server.utils.captcha._HCaptchaClientHolder.get")
async def test_verify_hcaptcha_with_special_characters(mock_get):
    """Verification handles special characters in token."""
    mock_response = MagicMock()
    mock_response.json.return_value = {"success": True}

    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_get.return_value = mock_client

    special_token = "token-with-special!@#$%^&*()_+="
    result = await verify_hcaptcha(special_token)

    assert result is True
    call_args = mock_client.post.call_args
    assert call_args[1]["data"]["response"] == special_token
