"""Tests for WebAuthn utilities."""

import base64
from datetime import datetime

from server.utils.webauthn_helper import (
    find_credential,
    generate_challenge,
    get_authentication_options,
    get_registration_options,
    get_rp_config,
    update_credential_last_used,
)


class TestWebAuthnUtilities:
    """Test WebAuthn utility functions."""

    def test_get_rp_config_development(self, monkeypatch):
        """Test RP config in development mode."""
        monkeypatch.setenv("AGENTGATE_ENV", "development")
        monkeypatch.delenv("WEBAUTHN_RP_ID", raising=False)

        rp_id, rp_name, origin = get_rp_config()

        assert rp_id == "localhost"
        assert rp_name == "AgentGate Dev"
        assert origin == "http://localhost:3000"

    def test_get_rp_config_production(self, monkeypatch):
        """Test RP config in production mode."""
        monkeypatch.setenv("AGENTGATE_ENV", "production")
        monkeypatch.delenv("WEBAUTHN_RP_ID", raising=False)

        rp_id, rp_name, origin = get_rp_config()

        assert rp_id == "agentgate.com"
        assert rp_name == "AgentGate"
        assert origin == "https://agentgate.com"

    def test_get_rp_config_custom(self, monkeypatch):
        """Test RP config with custom environment variables."""
        monkeypatch.setenv("AGENTGATE_ENV", "production")
        monkeypatch.setenv("WEBAUTHN_RP_ID", "custom.com")
        monkeypatch.setenv("WEBAUTHN_RP_NAME", "Custom App")
        monkeypatch.setenv("WEBAUTHN_ORIGIN", "https://custom.com")

        rp_id, rp_name, origin = get_rp_config()

        assert rp_id == "custom.com"
        assert rp_name == "Custom App"
        assert origin == "https://custom.com"

    def test_generate_challenge(self):
        """Test challenge generation."""
        challenge1 = generate_challenge()
        challenge2 = generate_challenge()

        assert len(challenge1) == 32
        assert len(challenge2) == 32

        # Should be unique
        assert challenge1 != challenge2

    def test_get_registration_options_no_credentials(self):
        """Test registration options without existing credentials."""
        result = get_registration_options(
            user_id=1,
            user_email="test@example.com",
            user_name="Test User",
            existing_credentials=None,
        )

        assert "options" in result
        assert "challenge" in result
        assert isinstance(result["challenge"], str)

    def test_get_registration_options_with_credentials(self):
        """Test registration options with existing credentials."""
        existing_creds = [
            {
                "credential_id": base64.b64encode(b"cred-1").decode("utf-8"),
                "transports": ["internal"],
            }
        ]

        result = get_registration_options(
            user_id=1,
            user_email="test@example.com",
            user_name="Test User",
            existing_credentials=existing_creds,
        )

        assert "options" in result
        assert "challenge" in result

    def test_get_authentication_options_no_credentials(self):
        """Test authentication options without credentials."""
        result = get_authentication_options(existing_credentials=None)

        assert "options" in result
        assert "challenge" in result

    def test_get_authentication_options_with_credentials(self):
        """Test authentication options with existing credentials."""
        existing_creds = [
            {
                "credential_id": base64.b64encode(b"cred-1").decode("utf-8"),
                "transports": ["internal"],
            }
        ]

        result = get_authentication_options(existing_credentials=existing_creds)

        assert "options" in result
        assert "challenge" in result

    def test_find_credential_found(self):
        """Test finding an existing credential."""
        cred_id = "credential-123"
        credentials = [
            {"credential_id": "other-cred", "name": "Other"},
            {"credential_id": cred_id, "name": "Target"},
            {"credential_id": "another-cred", "name": "Another"},
        ]

        result = find_credential(credentials, cred_id)

        assert result is not None
        assert result["credential_id"] == cred_id
        assert result["name"] == "Target"

    def test_find_credential_not_found(self):
        """Test finding a non-existent credential."""
        credentials = [
            {"credential_id": "cred-1", "name": "Cred 1"},
            {"credential_id": "cred-2", "name": "Cred 2"},
        ]

        result = find_credential(credentials, "non-existent")

        assert result is None

    def test_find_credential_empty_list(self):
        """Test finding credential in empty list."""
        result = find_credential([], "any-id")
        assert result is None

    def test_update_credential_last_used(self):
        """Test updating credential last_used timestamp."""
        credential = {
            "credential_id": "cred-123",
            "name": "Test Cred",
            "last_used": "2025-01-01T00:00:00Z",
        }

        updated = update_credential_last_used(credential)

        assert updated["credential_id"] == "cred-123"
        assert updated["name"] == "Test Cred"
        assert updated["last_used"] != "2025-01-01T00:00:00Z"

        # Verify it's a valid ISO format timestamp
        datetime.fromisoformat(updated["last_used"].replace("Z", "+00:00"))
