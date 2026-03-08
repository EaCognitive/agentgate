"""Tests for CAPTCHA utilities."""

import pytest

from server.utils.captcha import verify_hcaptcha


class TestCaptchaUtilities:
    """Test CAPTCHA utility functions."""

    @pytest.mark.asyncio
    async def test_verify_hcaptcha_development_mode(self, monkeypatch):
        """Test hCaptcha verification in development mode."""
        monkeypatch.delenv("HCAPTCHA_SECRET", raising=False)
        monkeypatch.setenv("AGENTGATE_ENV", "development")

        # Should pass in development without secret
        result = await verify_hcaptcha("fake-token")
        assert result is True

    @pytest.mark.asyncio
    async def test_verify_hcaptcha_test_mode(self, monkeypatch):
        """Test hCaptcha verification in test mode."""
        monkeypatch.delenv("HCAPTCHA_SECRET", raising=False)
        monkeypatch.setenv("AGENTGATE_ENV", "test")

        result = await verify_hcaptcha("fake-token")
        assert result is True

    @pytest.mark.asyncio
    async def test_verify_hcaptcha_production_without_secret(self, monkeypatch):
        """Test hCaptcha verification in production without secret."""
        monkeypatch.delenv("HCAPTCHA_SECRET", raising=False)
        monkeypatch.setenv("AGENTGATE_ENV", "production")

        with pytest.raises(ValueError, match="HCAPTCHA_SECRET not configured"):
            await verify_hcaptcha("fake-token")
