"""Authentication utility function tests."""

from server.routers.auth_utils import (
    _get_password_hash_sync as get_password_hash,
)
from server.routers.auth_utils import (
    _verify_password_sync as verify_password,
)

# ============== Utility Function Tests ==============


def test_verify_password_correct():
    """Test password verification with correct password."""
    hashed = get_password_hash("testpassword")
    assert verify_password("testpassword", hashed) is True


def test_verify_password_incorrect():
    """Test password verification with incorrect password."""
    hashed = get_password_hash("testpassword")
    assert verify_password("wrongpassword", hashed) is False


def test_get_password_hash_generates_unique_hashes():
    """Test that same password generates different hashes."""
    hash1 = get_password_hash("password")
    hash2 = get_password_hash("password")
    # bcrypt generates different salts, so hashes should differ
    assert hash1 != hash2
