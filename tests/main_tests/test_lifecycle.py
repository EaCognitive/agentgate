"""Lifecycle tests for server/main.py.

This covers:
- Application startup and shutdown lifecycle
- Admin user seeding
- Router mounting
- Application metadata
- Logging configuration
- Sentry configuration
- Main block execution
"""

import importlib
import os
import sys
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from pydantic import SecretStr

import server.main
import server.sentry_config
from ea_agentgate import __version__
from server.config import get_settings
from server.lifespan import lifespan, seed_default_admin
from server.main import app, main


def _refresh_main_bindings() -> None:
    """Refresh server.main module and local aliases used by tests."""
    module = importlib.import_module("server.main")
    globals()["app"] = module.app
    globals()["main"] = module.main


@pytest.fixture(autouse=True)
def reset_settings_cache():
    """Ensure settings are rebuilt per test so env patches take effect."""
    os.environ.setdefault("ALLOW_SECRET_KEY_FALLBACK", "true")
    get_settings.cache_clear()
    if "server.main" in sys.modules:
        del sys.modules["server.main"]
    _refresh_main_bindings()
    # server.main import eagerly resolves settings; clear again so each
    # individual test can control env-derived values via monkeypatch.
    get_settings.cache_clear()
    try:
        server.sentry_config.SentryManager.initialized = False
    except AttributeError:
        pass
    yield
    get_settings.cache_clear()
    if "server.main" in sys.modules:
        del sys.modules["server.main"]


@pytest.fixture(name="clean_env")
def _fixture_clean_env(monkeypatch):
    """Clean environment variables for consistent testing."""
    _ = monkeypatch
    monkeypatch.delenv("DEFAULT_ADMIN_EMAIL", raising=False)
    monkeypatch.delenv("DEFAULT_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("ALLOWED_ORIGINS", raising=False)
    monkeypatch.delenv("AGENTGATE_ENV", raising=False)
    monkeypatch.delenv("LOG_LEVEL", raising=False)
    monkeypatch.delenv("ENABLE_THREAT_DETECTION", raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)
    yield


@pytest.fixture(name="db_session")
def _fixture_db_session():
    """Mock async database session for testing."""
    mock_instance = MagicMock()
    mock_instance.execute = AsyncMock()
    mock_instance.commit = AsyncMock()
    mock_instance.refresh = AsyncMock()
    mock_instance.rollback = AsyncMock()

    @asynccontextmanager
    async def _session_ctx():
        yield mock_instance

    # Patch both possible locations since the import may have happened
    with (
        patch("server.main.get_session_context", _session_ctx),
        patch("server.models.get_session_context", _session_ctx),
    ):
        yield mock_instance


@pytest.mark.usefixtures("clean_env")
class TestLifespan:
    """Test application lifespan events."""

    @pytest.mark.asyncio
    async def test_lifespan_does_not_run_runtime_schema_init(self):
        """Lifespan startup must avoid runtime schema bootstrap side effects."""
        with (
            patch("server.lifespan.init_db") as mock_init_db,
            patch("server.lifespan.seed_default_admin") as mock_seed,
        ):
            fastapi_app = FastAPI()
            async with lifespan(fastapi_app):
                pass

            mock_init_db.assert_not_called()
            mock_seed.assert_called_once()

    @pytest.mark.asyncio
    async def test_lifespan_handles_app_parameter(self):
        """Test that lifespan properly handles the app parameter."""
        with patch("server.lifespan.init_db"), patch("server.lifespan.seed_default_admin"):
            fastapi_app = FastAPI()
            async with lifespan(fastapi_app):
                assert True

    @pytest.mark.asyncio
    async def test_lifespan_rejects_off_mode_in_production(self, monkeypatch):
        """Startup must fail when runtime Z3 mode is off in production."""
        monkeypatch.setenv("AGENTGATE_ENV", "production")
        monkeypatch.setenv("AGENTGATE_Z3_MODE", "off")
        monkeypatch.delenv("TESTING", raising=False)

        runtime_session = MagicMock()

        @asynccontextmanager
        async def _runtime_session_ctx():
            yield runtime_session

        with (
            patch("server.lifespan.init_db", new=AsyncMock()),
            patch("server.lifespan.seed_default_admin", new=AsyncMock()),
            patch(
                "server.lifespan.check_setup_required",
                new=AsyncMock(return_value=False),
            ),
            patch(
                "server.lifespan.get_session_context",
                _runtime_session_ctx,
            ),
            patch(
                "server.lifespan.get_ai_write_governance_mode",
                new=AsyncMock(return_value="strict"),
            ),
            patch(
                "server.lifespan.get_unknown_token_policy",
                new=AsyncMock(return_value="fail_closed"),
            ),
            patch(
                "server.lifespan.get_scoped_reads_enabled",
                new=AsyncMock(return_value=True),
            ),
        ):
            fastapi_app = FastAPI()
            with pytest.raises(RuntimeError, match="restricted to local/dev/test"):
                async with lifespan(fastapi_app):
                    pass


@pytest.mark.usefixtures("clean_env")
class TestSeedDefaultAdmin:
    """Test default admin user seeding functionality."""

    @pytest.mark.asyncio
    async def test_seed_default_admin_no_env_vars(self, db_session):
        """Test that seeding is skipped when env vars not set."""

        mock_settings = MagicMock()
        mock_settings.default_admin_email = None
        mock_settings.default_admin_password = None
        with patch("server.lifespan.get_settings", return_value=mock_settings):
            await seed_default_admin()
        db_session.execute.assert_not_called()

    @pytest.mark.asyncio
    async def test_seed_default_admin_only_email(self, db_session, monkeypatch):
        """Test that seeding is skipped when only email is set."""
        _ = monkeypatch

        mock_settings = MagicMock()
        mock_settings.default_admin_email = "admin@test.com"
        mock_settings.default_admin_password = None
        with patch("server.lifespan.get_settings", return_value=mock_settings):
            await seed_default_admin()
        db_session.execute.assert_not_called()

    @pytest.mark.asyncio
    async def test_seed_default_admin_only_password(self, db_session, monkeypatch):
        """Test that seeding is skipped when only password is set."""
        _ = monkeypatch

        mock_settings = MagicMock()
        mock_settings.default_admin_email = None
        mock_settings.default_admin_password = SecretStr("password123")
        with patch("server.lifespan.get_settings", return_value=mock_settings):
            await seed_default_admin()
        db_session.execute.assert_not_called()

    @pytest.mark.asyncio
    async def test_seed_default_admin_users_exist(self, monkeypatch):
        """Test that seeding is skipped when users already exist."""
        monkeypatch.setenv("DEFAULT_ADMIN_EMAIL", "admin@test.com")
        monkeypatch.setenv("DEFAULT_ADMIN_PASSWORD", "password123")

        mock_session = MagicMock()
        result = MagicMock()
        result.scalars.return_value.first.return_value = MagicMock()
        mock_session.execute = AsyncMock(return_value=result)

        @asynccontextmanager
        async def _mock_ctx():
            yield mock_session

        with patch("server.lifespan.get_session_context", _mock_ctx):
            await seed_default_admin()
            assert mock_session.execute.called
            mock_session.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_seed_default_admin_creates_user(self, monkeypatch):
        """Test that admin user is created when conditions are met."""
        monkeypatch.setenv("DEFAULT_ADMIN_EMAIL", "admin@test.com")
        monkeypatch.setenv("DEFAULT_ADMIN_PASSWORD", "password123")

        mock_session = MagicMock()
        result = MagicMock()
        result.scalars.return_value.first.return_value = None
        mock_session.execute = AsyncMock(return_value=result)
        mock_session.commit = AsyncMock()
        mock_session.add = MagicMock()

        async def _set_id(obj):
            """Simulate DB refresh by setting the id attribute."""
            if not hasattr(obj, "id") or obj.id is None:
                obj.id = 1

        mock_session.refresh = AsyncMock(side_effect=_set_id)

        @asynccontextmanager
        async def _mock_ctx():
            yield mock_session

        with (
            patch("server.lifespan.get_session_context", _mock_ctx),
            patch("server.lifespan.bcrypt.hashpw") as mock_hash,
            patch("server.lifespan.db_commit", AsyncMock()) as mock_commit,
        ):
            mock_hash.return_value = b"hashed_password"

            await seed_default_admin()
            # First add is the admin user, subsequent adds are PII permissions
            assert mock_session.add.call_count >= 1
            # Two commits: one for user creation, one for PII permissions
            assert mock_commit.call_count == 2


class TestRouterMounting:
    """Test that all routers are properly mounted."""

    def test_all_routers_mounted(self):
        """Test that all expected routers are included in the app."""
        with patch("server.lifespan.init_db"), patch("server.lifespan.seed_default_admin"):
            routes = [getattr(route, "path", "") for route in app.routes]
            assert any("/api/health" in route for route in routes)
            assert any("/metrics" in route for route in routes)
            assert any("/api/overview" in route for route in routes)

    def test_api_reference_route_present(self):
        """Test that the API reference route is included in the app."""
        with patch("server.lifespan.init_db"), patch("server.lifespan.seed_default_admin"):
            routes = [getattr(route, "path", "") for route in app.routes]
            assert any("/api/reference" in route for route in routes)


class TestApplicationMetadata:
    """Test FastAPI application metadata."""

    def test_app_title(self):
        """Test application title."""
        with patch("server.lifespan.init_db"), patch("server.lifespan.seed_default_admin"):
            assert app.title == "AgentGate Dashboard API"

    def test_app_version(self):
        """Test application version."""
        with patch("server.lifespan.init_db"), patch("server.lifespan.seed_default_admin"):
            assert app.version == __version__

    def test_app_metadata_fields(self):
        """Test other metadata fields."""
        with patch("server.lifespan.init_db"), patch("server.lifespan.seed_default_admin"):
            assert app.description is not None
            assert app.docs_url is None
            assert app.license_info["name"] == "MIT"


class TestLoggingConfiguration:
    """Test logging configuration."""

    def test_logging_setup_called_on_import(self):
        """Test that logging is configured on module import."""
        with (
            patch("server.logging_config.setup_logging") as mock_setup,
            patch("server.lifespan.init_db"),
            patch("server.lifespan.seed_default_admin"),
            patch("server.sentry_config.init_sentry"),
        ):
            importlib.reload(server.main)
            mock_setup.assert_called()

    @pytest.mark.usefixtures("clean_env")
    def test_logging_production_json(self, monkeypatch):
        """Test JSON logging in production."""
        monkeypatch.setenv("AGENTGATE_ENV", "production")
        monkeypatch.setenv("AGENTGATE_RUNTIME_PROFILE", "cloud_strict")
        monkeypatch.setenv("AGENTGATE_PROFILE", "cloud_strict")
        monkeypatch.setenv("ALLOW_PRODUCTION_LOCAL_AUTH", "true")
        monkeypatch.setenv("REDIS_URL", "redis://localhost:6379")
        monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost:5432/testdb")
        monkeypatch.setenv("AZURE_KEY_VAULT_URL", "https://unit-test.vault.azure.net/")
        with (
            patch("server.logging_config.setup_logging") as mock_setup,
            patch("server.lifespan.init_db"),
            patch("server.lifespan.seed_default_admin"),
            patch("server.sentry_config.init_sentry"),
            patch("server.rate_limiting.create_limiter") as mock_limiter,
            patch("server.config_secrets._load_allowed_key_vault_secrets", return_value={}),
        ):
            mock_limiter.return_value = MagicMock()
            get_settings.cache_clear()

            importlib.reload(server.main)
            call_kwargs = mock_setup.call_args[1]
            assert call_kwargs["use_json"] is True


class TestSentryConfiguration:
    """Test Sentry initialization."""

    def test_sentry_init_called(self):
        """Test that Sentry is initialized on module import."""

        # Reset the initialized flag BEFORE reloading main
        server.sentry_config.SentryManager.initialized = False

        # Remove cached module to force fresh import
        if "server.main" in sys.modules:
            del sys.modules["server.main"]
        _refresh_main_bindings()

        # Patch at the sentry_config module level before import
        with (
            patch("server.sentry_config.init_sentry") as mock_init_sentry,
            patch("server.lifespan.init_db"),
            patch("server.lifespan.seed_default_admin"),
            patch("server.logging_config.setup_logging"),
        ):
            # Force a fresh import by removing and re-importing
            if "server.main" in sys.modules:
                del sys.modules["server.main"]
            _refresh_main_bindings()
            importlib.reload(server.main)
            assert mock_init_sentry.call_count >= 1

    def test_sentry_manager_flag_can_reset(self):
        """Test that the Sentry manager initialized flag can be reset."""
        server.sentry_config.SentryManager.initialized = True
        server.sentry_config.SentryManager.initialized = False
        assert server.sentry_config.SentryManager.initialized is False


class TestMainExecution:
    """Test main block execution."""

    def test_main_block_runs_uvicorn(self):
        """Test that main() starts uvicorn server."""
        with (
            patch("uvicorn.run") as mock_uvicorn_run,
            patch("server.lifespan.init_db"),
            patch("server.lifespan.seed_default_admin"),
            patch("server.logging_config.setup_logging"),
            patch("server.sentry_config.init_sentry"),
        ):
            main()
            mock_uvicorn_run.assert_called_once()

    def test_main_block_uses_default_port(self):
        """Test that main() uses the default port when no override is set."""
        with (
            patch("uvicorn.run") as mock_uvicorn_run,
            patch("server.lifespan.init_db"),
            patch("server.lifespan.seed_default_admin"),
            patch("server.logging_config.setup_logging"),
            patch("server.sentry_config.init_sentry"),
        ):
            main()
            assert mock_uvicorn_run.call_args.kwargs["port"] == 8000
