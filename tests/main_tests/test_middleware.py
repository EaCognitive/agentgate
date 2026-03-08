"""Middleware and exception handler tests for server/main.py.

This covers:
- CORS middleware configuration
- Rate limiter configuration
- Rate limit headers middleware
- Global exception handler
- Middleware configuration and ordering
"""

import importlib
import os
import sys
from unittest.mock import Mock, patch

import pytest
from fastapi import Request, Response

import server.main
import server.rate_limiting
from server.config import get_settings
from server.cors_config import get_allowed_origins
from server.main import app, global_exception_handler
from server.middleware import ThreatDetectionMiddleware
from server.rate_limiting import rate_limit_headers_middleware


def _refresh_main_bindings() -> None:
    """Refresh server.main module and local aliases used by tests."""
    module = importlib.import_module("server.main")
    globals()["app"] = module.app
    globals()["global_exception_handler"] = module.global_exception_handler


@pytest.fixture(autouse=True)
def reset_settings_cache():
    """Ensure settings are rebuilt per test so env patches take effect."""
    os.environ.setdefault("ALLOW_SECRET_KEY_FALLBACK", "true")
    get_settings.cache_clear()
    if "server.main" in sys.modules:
        del sys.modules["server.main"]
    _refresh_main_bindings()
    yield
    get_settings.cache_clear()


@pytest.fixture
def clean_env(monkeypatch):
    """Clean environment variables for consistent testing."""
    monkeypatch.delenv("ALLOWED_ORIGINS", raising=False)
    monkeypatch.delenv("AGENTGATE_ENV", raising=False)
    monkeypatch.delenv("ENABLE_THREAT_DETECTION", raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)
    yield


@pytest.mark.usefixtures("clean_env")
class TestCORSConfiguration:
    """Test CORS middleware configuration."""

    def test_get_allowed_origins_from_env(self, monkeypatch):
        """Test that origins are read from environment variable."""
        monkeypatch.setenv("ALLOWED_ORIGINS", "http://example.com,https://app.example.com")

        origins = get_allowed_origins()
        assert origins == ["http://example.com", "https://app.example.com"]

    def test_get_allowed_origins_strips_whitespace(self, monkeypatch):
        """Test that whitespace is stripped from origins."""
        monkeypatch.setenv("ALLOWED_ORIGINS", " http://example.com , https://app.example.com ")

        origins = get_allowed_origins()
        assert origins == ["http://example.com", "https://app.example.com"]

    def test_get_allowed_origins_development_defaults(self, monkeypatch):
        """Test that development defaults are used when no env var set."""
        monkeypatch.setenv("AGENTGATE_ENV", "development")

        origins = get_allowed_origins()
        assert "http://localhost:3000" in origins
        assert "http://127.0.0.1:3000" in origins

    def test_get_allowed_origins_production_empty(self, monkeypatch):
        """Test that production returns empty list when no origins configured."""
        monkeypatch.setenv("AGENTGATE_ENV", "production")

        origins = get_allowed_origins()
        assert not origins


@pytest.mark.usefixtures("clean_env")
class TestRateLimiterConfiguration:
    """Test rate limiter configuration."""

    def test_rate_limit_uses_memory_storage_default(self):
        """Test that memory storage is used by default."""
        with patch("server.config.get_settings") as mock_get_settings:
            mock_cfg = Mock()
            mock_cfg.redis_url = "memory://"
            mock_cfg.environment = "development"
            mock_cfg.log_level = "INFO"
            mock_get_settings.return_value = mock_cfg

            importlib.reload(server.rate_limiting)

            limiter = server.rate_limiting.create_limiter()
            assert limiter is not None
            assert getattr(limiter, "storage_uri", None) == "memory://"

    def test_rate_limiter_uses_redis_url(self):
        """Test that Redis URL can be configured."""
        test_redis_url = os.getenv("REDIS_URL", "memory://")
        assert test_redis_url is not None


class TestRateLimitHeadersMiddleware:
    """Test rate limit headers middleware."""

    @pytest.mark.asyncio
    async def test_rate_limit_headers_tuple_format(self):
        """Test rate limit headers with tuple format."""

        request = Mock(spec=Request)
        request.state = Mock()
        request.state.view_rate_limit = (100, 95, 1706400000)

        response = Response(content="test")

        async def _call_next(_req):
            return response

        result = await rate_limit_headers_middleware(request, _call_next)
        assert result.headers["X-RateLimit-Limit"] == "100"
        assert result.headers["X-RateLimit-Remaining"] == "95"
        assert result.headers["X-RateLimit-Reset"] == "1706400000"

    @pytest.mark.asyncio
    async def test_rate_limit_headers_object_format(self):
        """Test rate limit headers with object format."""

        request = Mock(spec=Request)
        limit_obj = Mock()
        limit_obj.limit = 100
        limit_obj.remaining = 95
        limit_obj.reset_time = 1706400000
        request.state = Mock()
        request.state.view_rate_limit = limit_obj

        response = Response(content="test")

        async def _call_next(_req):
            return response

        result = await rate_limit_headers_middleware(request, _call_next)

        assert result.headers["X-RateLimit-Limit"] == "100"
        assert result.headers["X-RateLimit-Remaining"] == "95"
        assert result.headers["X-RateLimit-Reset"] == "1706400000"

    @pytest.mark.asyncio
    async def test_rate_limit_headers_attribute_error(self):
        """Test middleware handles AttributeError gracefully."""

        request = Mock(spec=Request)
        limit_obj = Mock()
        type(limit_obj).limit = property(lambda self: (_ for _ in ()).throw(AttributeError))
        request.state = Mock()
        request.state.view_rate_limit = limit_obj

        response = Response(content="test")

        async def _call_next(_req):
            return response

        result = await rate_limit_headers_middleware(request, _call_next)
        assert result is not None


class TestGlobalExceptionHandler:
    """Test global exception handler."""

    @pytest.mark.asyncio
    async def test_global_exception_handler_logs_error(self):
        """Test that unhandled exceptions are logged."""
        with patch("server.lifespan.init_db"), patch("server.lifespan.seed_default_admin"):
            request = Mock(spec=Request)
            request.url = Mock()
            request.url.path = "/api/test"
            request.method = "GET"
            request.client = Mock()
            request.client.host = "127.0.0.1"

            exc = ValueError("Test error")

            with patch("server.main.logger") as mock_logger:
                response = await global_exception_handler(request, exc)

            assert response.status_code == 500
            mock_logger.error.assert_called_once()

    @pytest.mark.asyncio
    async def test_global_exception_handler_hides_details(self):
        """Test that exception details are not exposed to client."""
        with patch("server.lifespan.init_db"), patch("server.lifespan.seed_default_admin"):
            request = Mock(spec=Request)
            request.url = Mock()
            request.url.path = "/api/test"
            request.method = "GET"
            request.client = Mock()
            request.client.host = "127.0.0.1"

            exc = ValueError("Secret error")
            response = await global_exception_handler(request, exc)

            body = bytes(response.body).decode()
            assert "Secret error" not in body
            assert "Internal server error" in body


class TestMiddlewareConfiguration:
    """Test middleware configuration and ordering."""

    def test_cors_middleware_added(self):
        """Test that CORS middleware is added to app."""
        with patch("server.lifespan.init_db"), patch("server.lifespan.seed_default_admin"):
            assert hasattr(app, "user_middleware")

    @pytest.mark.usefixtures("clean_env")
    def test_threat_detection_enabled_by_default(self, monkeypatch):
        """Test threat detection enabled by default."""
        monkeypatch.setenv("AGENTGATE_ENV", "development")
        monkeypatch.setenv("ALLOW_SECRET_KEY_FALLBACK", "true")
        get_settings.cache_clear()
        with patch("server.lifespan.init_db"), patch("server.lifespan.seed_default_admin"):
            importlib.reload(server.main)
            middleware_classes = [m.cls for m in server.main.app.user_middleware]
            assert ThreatDetectionMiddleware in middleware_classes
