"""Environment variable and secret key tests."""

import os
from unittest.mock import patch

import pytest

from server.routers.auth_utils import _get_secret_key


def test_get_secret_key_production_without_key():
    """Test SECRET_KEY raises RuntimeError in production when not set."""
    env = {"AGENTGATE_ENV": "production"}
    with patch.dict(os.environ, env, clear=True):
        with pytest.raises(RuntimeError, match="SECRET_KEY environment variable not set"):
            _get_secret_key()


def test_get_secret_key_too_short():
    """Test SECRET_KEY raises ValueError when too short."""
    with patch.dict(
        os.environ, {"SECRET_KEY": "short", "AGENTGATE_ENV": "production"}, clear=False
    ):
        with pytest.raises(ValueError, match="SECRET_KEY must be at least 32 characters"):
            _get_secret_key()


def test_get_secret_key_development_fallback():
    """Test SECRET_KEY uses fallback in development."""
    with patch.dict(os.environ, {"AGENTGATE_ENV": "development"}, clear=False):
        # Remove SECRET_KEY
        original_key = os.environ.pop("SECRET_KEY", None)
        try:
            key = _get_secret_key()
            assert key == "dev-secret-key-for-local-development-only-32chars"
        finally:
            if original_key:
                os.environ["SECRET_KEY"] = original_key


def test_get_secret_key_test_fallback():
    """Test SECRET_KEY uses fallback in test mode."""
    with patch.dict(os.environ, {"AGENTGATE_ENV": "test"}, clear=False):
        # Remove SECRET_KEY
        original_key = os.environ.pop("SECRET_KEY", None)
        try:
            key = _get_secret_key()
            assert key == "dev-secret-key-for-local-development-only-32chars"
        finally:
            if original_key:
                os.environ["SECRET_KEY"] = original_key


def test_get_secret_key_with_valid_key():
    """Test SECRET_KEY with valid key length."""
    valid_key = "a" * 32  # Exactly 32 characters
    with patch.dict(
        os.environ, {"SECRET_KEY": valid_key, "AGENTGATE_ENV": "production"}, clear=False
    ):
        key = _get_secret_key()
        assert key == valid_key
