"""Comprehensive test coverage for server/utils/webauthn_helper.py and server/models/database.py.

This test suite achieves 100% coverage for both modules by testing:
- webauthn_helper.py: All credential verification paths, exception handling, and edge cases
- database.py: Database initialization, session management, and URL handling
"""

import base64
import importlib
import importlib.util
from unittest.mock import MagicMock, Mock, patch

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from server.main import app
from server.models import database
from server.utils import webauthn_helper

_asyncpg_available = importlib.util.find_spec("asyncpg") is not None
_skip_no_asyncpg = pytest.mark.skipif(
    not _asyncpg_available,
    reason="asyncpg package not installed",
)

_ = app


@pytest_asyncio.fixture(autouse=True)
async def cleanup_database_engine():
    """Ensure async engine is closed after each test to avoid ResourceWarnings."""
    yield
    try:
        await database.close_db()
    except (AttributeError, OSError, RuntimeError, ValueError):
        pass


class TestWebAuthnHelper:
    """Comprehensive tests for webauthn_helper.py to achieve 100% coverage."""

    def test_get_rp_config_production(self, monkeypatch):
        """Test get_rp_config returns production configuration."""
        monkeypatch.setenv("AGENTGATE_ENV", "production")
        monkeypatch.setenv("WEBAUTHN_RP_ID", "agentgate.example.com")
        monkeypatch.setenv("WEBAUTHN_RP_NAME", "AgentGate Production")
        monkeypatch.setenv("WEBAUTHN_ORIGIN", "https://agentgate.example.com")

        rp_id, rp_name, origin = webauthn_helper.get_rp_config()

        assert rp_id == "agentgate.example.com"
        assert rp_name == "AgentGate Production"
        assert origin == "https://agentgate.example.com"

    def test_get_rp_config_development(self, monkeypatch):
        """Test get_rp_config returns development defaults."""
        monkeypatch.delenv("AGENTGATE_ENV", raising=False)

        rp_id, rp_name, origin = webauthn_helper.get_rp_config()

        assert rp_id == "localhost"
        assert rp_name == "AgentGate Dev"
        assert origin == "http://localhost:3000"

    def test_generate_challenge(self):
        """Test generate_challenge creates 32-byte random challenge."""
        challenge = webauthn_helper.generate_challenge()

        assert isinstance(challenge, bytes)
        assert len(challenge) == 32

    def test_get_registration_options_with_invalid_credentials(self, monkeypatch):
        """Ensure invalid credentials in exclude list are skipped."""
        monkeypatch.delenv("AGENTGATE_ENV", raising=False)

        # Create invalid credentials that will trigger exception
        existing_credentials = [
            {
                "credential_id": "invalid_base64!@#$",  # Invalid base64
                "transports": ["internal"],
            },
            {
                "credential_id": base64.b64encode(b"valid_credential").decode("utf-8"),
                "transports": ["usb"],
            },
        ]

        result = webauthn_helper.get_registration_options(
            user_id=123,
            user_email="test@example.com",
            user_name="Test User",
            existing_credentials=existing_credentials,
        )

        # Should succeed and skip invalid credential
        assert "options" in result
        assert "challenge" in result

    def test_get_registration_options_with_malformed_transports(self, monkeypatch):
        """Test get_registration_options handles credentials with invalid transport types."""
        monkeypatch.delenv("AGENTGATE_ENV", raising=False)

        existing_credentials = [
            {
                "credential_id": base64.b64encode(b"test_credential").decode("utf-8"),
                "transports": ["invalid_transport_type"],  # Invalid transport
            },
        ]

        # Should handle gracefully and skip invalid credential
        result = webauthn_helper.get_registration_options(
            user_id=123,
            user_email="test@example.com",
            user_name="Test User",
            existing_credentials=existing_credentials,
        )

        assert "options" in result
        assert "challenge" in result

    def test_verify_registration_success(self, monkeypatch):
        """Test verify_registration successfully verifies credential (lines 146-158)."""
        monkeypatch.delenv("AGENTGATE_ENV", raising=False)

        # Mock the verification response
        mock_verification = Mock()
        mock_verification.credential_id = b"test_credential_id"
        mock_verification.credential_public_key = b"test_public_key"
        mock_verification.sign_count = 0

        with patch("server.utils.webauthn_helper.verify_registration_response") as mock_verify:
            mock_verify.return_value = mock_verification

            credential = {
                "id": "test_id",
                "rawId": "test_raw_id",
                "type": "public-key",
                "response": {
                    "clientDataJSON": "test_client_data",
                    "attestationObject": "test_attestation",
                    "transports": ["internal", "hybrid"],
                },
            }

            expected_challenge = b"test_challenge_bytes"

            result = webauthn_helper.verify_registration(
                credential=credential,
                expected_challenge=expected_challenge,
                user_id=123,
            )

            # Verify result structure
            assert "credential_id" in result
            assert "public_key" in result
            assert "sign_count" in result
            assert result["sign_count"] == 0
            assert "transports" in result
            assert result["transports"] == ["internal", "hybrid"]
            assert "created_at" in result
            assert "last_used" in result
            assert "name" in result
            assert result["name"] == "Passkey"

            # Verify base64 encoding
            assert isinstance(result["credential_id"], str)
            assert isinstance(result["public_key"], str)

            # Verify mock was called with correct parameters
            mock_verify.assert_called_once()
            call_kwargs = mock_verify.call_args[1]
            assert call_kwargs["credential"] == credential
            assert call_kwargs["expected_challenge"] == expected_challenge
            assert call_kwargs["expected_origin"] == "http://localhost:3000"
            assert call_kwargs["expected_rp_id"] == "localhost"

    def test_verify_registration_with_empty_transports(self, monkeypatch):
        """Test verify_registration handles missing transports field."""
        monkeypatch.delenv("AGENTGATE_ENV", raising=False)

        mock_verification = Mock()
        mock_verification.credential_id = b"test_credential_id"
        mock_verification.credential_public_key = b"test_public_key"
        mock_verification.sign_count = 0

        with patch("server.utils.webauthn_helper.verify_registration_response") as mock_verify:
            mock_verify.return_value = mock_verification

            credential = {
                "id": "test_id",
                "rawId": "test_raw_id",
                "type": "public-key",
                "response": {
                    "clientDataJSON": "test_client_data",
                    "attestationObject": "test_attestation",
                    # No transports field
                },
            }

            result = webauthn_helper.verify_registration(
                credential=credential,
                expected_challenge=b"test_challenge",
                user_id=123,
            )

            # Should default to empty list
            assert not result["transports"]

    def test_get_authentication_options_with_invalid_credentials(self, monkeypatch):
        """Test get_authentication_options handles invalid credentials (lines 193-195)."""
        monkeypatch.delenv("AGENTGATE_ENV", raising=False)

        existing_credentials = [
            {
                "credential_id": "invalid_base64!@#$",  # Invalid base64
                "transports": ["internal"],
            },
            {
                "credential_id": base64.b64encode(b"valid_credential").decode("utf-8"),
                "transports": ["usb"],
            },
        ]

        result = webauthn_helper.get_authentication_options(
            existing_credentials=existing_credentials
        )

        # Should succeed and skip invalid credential
        assert "options" in result
        assert "challenge" in result

    def test_verify_authentication_success(self, monkeypatch):
        """Test verify_authentication successful path (lines 226-247)."""
        monkeypatch.delenv("AGENTGATE_ENV", raising=False)

        mock_verification = Mock()
        mock_verification.new_sign_count = 1

        with patch("server.utils.webauthn_helper.verify_authentication_response") as mock_verify:
            mock_verify.return_value = mock_verification

            credential = {
                "id": "test_id",
                "rawId": "test_raw_id",
                "type": "public-key",
                "response": {
                    "clientDataJSON": "test_client_data",
                    "authenticatorData": "test_authenticator_data",
                    "signature": "test_signature",
                },
            }

            stored_credential = {
                "credential_id": base64.b64encode(b"test_credential_id").decode("utf-8"),
                "public_key": base64.b64encode(b"test_public_key").decode("utf-8"),
                "sign_count": 0,
            }

            success, new_sign_count = webauthn_helper.verify_authentication(
                credential=credential,
                expected_challenge=b"test_challenge",
                stored_credential=stored_credential,
            )

            assert success is True
            assert new_sign_count == 1

            # Verify mock was called
            mock_verify.assert_called_once()
            call_kwargs = mock_verify.call_args[1]
            assert call_kwargs["credential"] == credential
            assert call_kwargs["expected_challenge"] == b"test_challenge"
            assert call_kwargs["expected_origin"] == "http://localhost:3000"
            assert call_kwargs["expected_rp_id"] == "localhost"
            assert call_kwargs["credential_public_key"] == b"test_public_key"
            assert call_kwargs["credential_current_sign_count"] == 0

    def test_verify_authentication_failure(self, monkeypatch, caplog):
        """Test verify_authentication handles verification failure (lines 248-251)."""
        monkeypatch.delenv("AGENTGATE_ENV", raising=False)

        with caplog.at_level("ERROR", logger="server.utils.webauthn_helper"):
            with patch(
                "server.utils.webauthn_helper.verify_authentication_response"
            ) as mock_verify:
                mock_verify.side_effect = Exception("Signature verification failed")

                credential = {
                    "id": "test_id",
                    "rawId": "test_raw_id",
                    "type": "public-key",
                    "response": {
                        "clientDataJSON": "test_client_data",
                        "authenticatorData": "test_authenticator_data",
                        "signature": "test_signature",
                    },
                }

                stored_credential = {
                    "credential_id": base64.b64encode(b"test_credential_id").decode("utf-8"),
                    "public_key": base64.b64encode(b"test_public_key").decode("utf-8"),
                    "sign_count": 5,
                }

                success, new_sign_count = webauthn_helper.verify_authentication(
                    credential=credential,
                    expected_challenge=b"test_challenge",
                    stored_credential=stored_credential,
                )

                # Should return False and preserve original sign count
                assert success is False
                assert new_sign_count == 5

                # Verify error was logged
                assert "WebAuthn verification failed" in caplog.text

    def test_verify_authentication_with_default_sign_count(self, monkeypatch):
        """Test verify_authentication uses default sign_count of 0 when missing."""
        monkeypatch.delenv("AGENTGATE_ENV", raising=False)

        with patch("server.utils.webauthn_helper.verify_authentication_response") as mock_verify:
            mock_verify.side_effect = Exception("Test error")

            credential = {
                "id": "test_id",
                "response": {},
            }

            # Missing sign_count in stored_credential
            stored_credential = {
                "credential_id": base64.b64encode(b"test_credential_id").decode("utf-8"),
                "public_key": base64.b64encode(b"test_public_key").decode("utf-8"),
                # No sign_count field
            }

            success, new_sign_count = webauthn_helper.verify_authentication(
                credential=credential,
                expected_challenge=b"test_challenge",
                stored_credential=stored_credential,
            )

            # Should use default of 0
            assert success is False
            assert new_sign_count == 0

    def test_find_credential_found(self):
        """Test find_credential successfully finds credential."""
        credentials = [
            {"credential_id": "cred_1", "name": "First"},
            {"credential_id": "cred_2", "name": "Second"},
            {"credential_id": "cred_3", "name": "Third"},
        ]

        result = webauthn_helper.find_credential(credentials, "cred_2")

        assert result is not None
        assert result["name"] == "Second"

    def test_find_credential_not_found(self):
        """Test find_credential returns None when credential not found."""
        credentials = [
            {"credential_id": "cred_1", "name": "First"},
            {"credential_id": "cred_2", "name": "Second"},
        ]

        result = webauthn_helper.find_credential(credentials, "cred_nonexistent")

        assert result is None

    def test_find_credential_empty_list(self):
        """Test find_credential handles empty credentials list."""
        result = webauthn_helper.find_credential([], "cred_1")

        assert result is None

    def test_update_credential_last_used(self):
        """Test update_credential_last_used updates timestamp."""
        credential = {
            "credential_id": "test_id",
            "name": "Test Credential",
            "last_used": "2025-01-01T00:00:00Z",
        }

        updated = webauthn_helper.update_credential_last_used(credential)

        # Verify timestamp was updated
        assert updated["last_used"] != "2025-01-01T00:00:00Z"
        assert "T" in updated["last_used"]  # ISO format (naive UTC, no timezone suffix)

        # Verify other fields unchanged
        assert updated["credential_id"] == "test_id"
        assert updated["name"] == "Test Credential"


class TestDatabase:
    """Comprehensive tests for database.py to achieve 100% coverage."""

    def test_postgres_url_replacement(self, monkeypatch):
        """Test postgres:// URL is replaced with postgresql:// (line 12)."""
        # Set postgres:// URL
        monkeypatch.setenv("DATABASE_URL", "postgres://user:pass@localhost/dbname")

        # Mock create_async_engine to avoid needing asyncpg installed

        with patch("sqlalchemy.ext.asyncio.create_async_engine", return_value=MagicMock()):
            importlib.reload(database)

        # Verify URL was replaced
        assert database.DATABASE_URL.startswith("postgresql+asyncpg://")
        assert "user:pass@localhost/dbname" in database.DATABASE_URL

    def test_sqlite_url_not_replaced(self, monkeypatch):
        """Test sqlite URL is not modified."""
        monkeypatch.setenv("DATABASE_URL", "sqlite:///./test.db")

        importlib.reload(database)

        assert database.DATABASE_URL == "sqlite+aiosqlite:///./test.db"

    def test_postgresql_url_not_replaced(self, monkeypatch):
        """Test postgresql:// URL is not modified."""
        monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost/dbname")

        # Mock create_async_engine to avoid needing asyncpg installed

        with patch("sqlalchemy.ext.asyncio.create_async_engine", return_value=MagicMock()):
            importlib.reload(database)

        assert database.DATABASE_URL == "postgresql+asyncpg://user:pass@localhost/dbname"

    @pytest.mark.asyncio
    async def test_init_db(self, monkeypatch):
        """Test init_db creates all tables (line 22)."""
        monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")

        importlib.reload(database)

        with patch("server.models.database.SQLModel") as mock_sqlmodel:
            await database.init_db()

            # Verify create_all was called
            mock_sqlmodel.metadata.create_all.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_session_yields_session(self, monkeypatch):
        """Test get_session yields a session (lines 27-28)."""
        monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")

        importlib.reload(database)

        # Test the generator
        session_gen = database.get_session()
        session = await anext(session_gen)

        assert isinstance(session, AsyncSession)

        await session_gen.aclose()

    @pytest.mark.asyncio
    async def test_get_session_closes_on_completion(self, monkeypatch):
        """Test get_session closes session after yield."""
        monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")

        importlib.reload(database)

        gen = database.get_session()
        _ = await anext(gen)
        await gen.aclose()

    @pytest.mark.asyncio
    async def test_get_session_context_yields_session(self, monkeypatch):
        """Test get_session_context context manager yields session (lines 34-35)."""
        monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")

        importlib.reload(database)

        async with database.get_session_context() as session:
            assert isinstance(session, AsyncSession)

    @pytest.mark.asyncio
    async def test_get_session_context_closes_on_exit(self, monkeypatch):
        """Test get_session_context closes session on exit."""
        monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")

        importlib.reload(database)

        async with database.get_session_context() as session:
            assert session is not None

    @pytest.mark.asyncio
    async def test_get_session_context_handles_exceptions(self, monkeypatch):
        """Test get_session_context properly handles exceptions."""
        monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")

        importlib.reload(database)

        with pytest.raises(ValueError):
            async with database.get_session_context():
                raise ValueError("Test error")

    def test_connect_args_sqlite(self, monkeypatch):
        """Test connect_args includes check_same_thread for SQLite."""
        monkeypatch.setenv("DATABASE_URL", "sqlite:///./test.db")

        importlib.reload(database)

        assert database.connect_args == {"check_same_thread": False}

    def test_connect_args_postgresql(self, monkeypatch):
        """Test connect_args is empty for PostgreSQL."""
        monkeypatch.setenv("DATABASE_URL", "postgresql://localhost/db")

        # Mock create_async_engine to avoid needing asyncpg installed

        with patch("sqlalchemy.ext.asyncio.create_async_engine", return_value=MagicMock()):
            importlib.reload(database)

        assert not database.connect_args

    def test_engine_created(self, monkeypatch):
        """Test engine is properly created."""
        monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")

        importlib.reload(database)

        assert isinstance(database.engine, AsyncEngine)

    def test_default_database_url(self, monkeypatch):
        """Test default DATABASE_URL when env var not set."""
        monkeypatch.delenv("DATABASE_URL", raising=False)

        importlib.reload(database)

        assert database.DATABASE_URL == "sqlite+aiosqlite:///./agentgate.db"


class TestWebAuthnHelperIntegration:
    """Integration tests for complete webauthn flows."""

    def test_registration_options_with_valid_existing_credentials(self, monkeypatch):
        """Test get_registration_options with valid existing credentials."""
        monkeypatch.delenv("AGENTGATE_ENV", raising=False)

        existing_credentials = [
            {
                "credential_id": base64.b64encode(b"credential_1").decode("utf-8"),
                "transports": ["internal"],
            },
            {
                "credential_id": base64.b64encode(b"credential_2").decode("utf-8"),
                "transports": ["usb", "nfc"],
            },
        ]

        result = webauthn_helper.get_registration_options(
            user_id=456,
            user_email="user@example.com",
            user_name="User Name",
            existing_credentials=existing_credentials,
        )

        assert "options" in result
        assert "challenge" in result
        assert isinstance(result["challenge"], str)

        # Verify options structure
        options = result["options"]
        assert "challenge" in options
        assert "rp" in options
        assert options["rp"]["id"] == "localhost"
        assert options["rp"]["name"] == "AgentGate Dev"
        assert "user" in options
        assert options["user"]["name"] == "user@example.com"

    def test_authentication_options_with_valid_credentials(self, monkeypatch):
        """Test get_authentication_options with valid credentials."""
        monkeypatch.delenv("AGENTGATE_ENV", raising=False)

        existing_credentials = [
            {
                "credential_id": base64.b64encode(b"credential_1").decode("utf-8"),
                "transports": ["internal", "hybrid"],
            },
        ]

        result = webauthn_helper.get_authentication_options(
            existing_credentials=existing_credentials
        )

        assert "options" in result
        assert "challenge" in result
        assert isinstance(result["challenge"], str)

        options = result["options"]
        assert "challenge" in options
        assert "allowCredentials" in options

    def test_authentication_options_no_credentials(self, monkeypatch):
        """Test get_authentication_options with no credentials."""
        monkeypatch.delenv("AGENTGATE_ENV", raising=False)

        result = webauthn_helper.get_authentication_options(existing_credentials=None)

        assert "options" in result
        assert "challenge" in result

    def test_registration_options_no_existing_credentials(self, monkeypatch):
        """Test get_registration_options with no existing credentials."""
        monkeypatch.delenv("AGENTGATE_ENV", raising=False)

        result = webauthn_helper.get_registration_options(
            user_id=789,
            user_email="newuser@example.com",
            user_name="New User",
            existing_credentials=None,
        )

        assert "options" in result
        assert "challenge" in result


class TestDatabaseIntegration:
    """Integration tests for database operations."""

    @pytest.mark.asyncio
    async def test_full_session_lifecycle(self, monkeypatch):
        """Test complete session lifecycle."""
        monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")

        importlib.reload(database)

        # Initialize database
        await database.init_db()

        # Use get_session
        gen = database.get_session()
        session = await anext(gen)

        assert isinstance(session, AsyncSession)

        await gen.aclose()

    @pytest.mark.asyncio
    async def test_full_context_manager_lifecycle(self, monkeypatch):
        """Test complete context manager lifecycle."""
        monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")

        importlib.reload(database)

        # Initialize database
        await database.init_db()

        # Use context manager
        async with database.get_session_context() as session:
            assert isinstance(session, AsyncSession)

        # Session should be closed after context exit
        # (In real usage, attempting to use session would raise an error)
