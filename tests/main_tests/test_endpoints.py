"""Endpoint tests for server/main.py.

This covers:
- Health check endpoint
- Prometheus metrics endpoint
- Overview stats endpoint
- System info configuration
- Edge case handling in overview
"""

import importlib
import os
import sys
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import server.main
from server.config import get_settings
from server.main import app, limiter, metrics
from server.models import TraceStatus
from server.routers.auth import get_current_user


def _refresh_main_bindings() -> None:
    """Refresh server.main module and local aliases used by tests."""
    module = importlib.import_module("server.main")
    globals()["app"] = module.app
    globals()["limiter"] = module.limiter
    globals()["metrics"] = module.metrics


@pytest.fixture(autouse=True)
def reset_settings_cache():
    """Ensure settings are rebuilt per test."""
    os.environ.setdefault("ALLOW_SECRET_KEY_FALLBACK", "true")
    get_settings.cache_clear()
    if "server.main" in sys.modules:
        del sys.modules["server.main"]
    _refresh_main_bindings()
    yield
    get_settings.cache_clear()


@pytest.fixture(name="db_session")
def _fixture_db_session():
    """Mock async database session for testing."""
    mock_instance = MagicMock()
    mock_instance.execute = AsyncMock()

    @asynccontextmanager
    async def _session_ctx():
        yield mock_instance

    with patch("server.main.get_session_context", _session_ctx):
        yield mock_instance


def _patch_async_session(mock_session):
    """Patch server.main.get_session_context to yield a mock async session."""

    @asynccontextmanager
    async def _session_ctx():
        yield mock_session

    return patch("server.main.get_session_context", _session_ctx)


def _current_user_override() -> object:
    """Return a placeholder authenticated user for dependency overrides."""
    return object()


class TestHealthCheckEndpoint:
    """Test health check endpoint."""

    def test_health_check_returns_200(self):
        """Readiness alias should return 200 when dependencies are healthy."""
        readiness_report = {
            "ready": True,
            "profile": "local_compat",
            "checks": {
                "database": {"ok": True},
                "schema": {"ok": True},
                "guardrails_release": {"ok": True},
                "redis": {"ok": True},
                "solver": {"ok": True},
            },
        }
        with (
            patch("server.lifespan.seed_default_admin"),
            patch(
                "server.routers.health.evaluate_readiness",
                new=AsyncMock(return_value=MagicMock(**readiness_report)),
            ),
        ):
            client = TestClient(app)
            response = client.get("/api/health")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "healthy"
            assert "version" in data
            assert "distributed_health_monitor" in data

    def test_readiness_returns_503_when_unhealthy(self):
        """Readiness endpoint should fail closed on unhealthy dependency checks."""
        readiness_report = {
            "ready": False,
            "profile": "cloud_strict",
            "checks": {
                "database": {"ok": True},
                "schema": {"ok": True},
                "guardrails_release": {"ok": False},
                "redis": {"ok": True},
                "solver": {"ok": True},
            },
        }
        with (
            patch("server.lifespan.seed_default_admin"),
            patch(
                "server.routers.health.evaluate_readiness",
                new=AsyncMock(return_value=MagicMock(**readiness_report)),
            ),
        ):
            client = TestClient(app)
            response = client.get("/health/readiness")
            assert response.status_code == 503
            assert response.json()["readiness"] == "not_ready"

    def test_liveness_does_not_call_dependency_checks(self):
        """Liveness probe performs zero external readiness checks."""
        mock_readiness = AsyncMock()
        with (
            patch("server.lifespan.seed_default_admin"),
            patch("server.routers.health.evaluate_readiness", new=mock_readiness),
        ):
            client = TestClient(app)
            response = client.get("/health/liveness")
            assert response.status_code == 200
            assert response.json()["status"] == "alive"
            mock_readiness.assert_not_called()

    def test_distributed_health_endpoint_returns_payload(self):
        """Distributed health endpoint should always return monitor state payload."""
        with patch("server.lifespan.seed_default_admin"):
            client = TestClient(app)
            response = client.get("/api/health/distributed")
            assert response.status_code == 200
            payload = response.json()
            assert "enabled" in payload
            assert "running" in payload
            assert "overall_status" in payload


class TestMetricsEndpoint:
    """Test Prometheus metrics endpoint."""

    def test_metrics_endpoint_returns_200(self):
        """Test that metrics endpoint returns 200 status."""
        with patch("server.lifespan.init_db"), patch("server.lifespan.seed_default_admin"):
            client = TestClient(app)
            response = client.get("/metrics")
            assert response.status_code == 200
            assert "text/plain" in response.headers["content-type"]

    @pytest.mark.asyncio
    async def test_metrics_function_direct(self):
        """Test metrics function logic directly."""
        with patch("server.lifespan.init_db"), patch("server.lifespan.seed_default_admin"):
            with patch("server.main.generate_latest") as mock_gen:
                mock_gen.return_value = b"metrics_data"
                response = await metrics()
                assert response.body == b"metrics_data"


class TestOverviewEndpoint:
    """Test overview stats endpoint."""

    def test_overview_with_no_traces_named(self, db_session):
        """Test overview endpoint when no traces exist."""
        with (
            patch("server.lifespan.init_db"),
            patch("server.lifespan.seed_default_admin"),
            _patch_async_session(db_session),
        ):
            trace_result = MagicMock()
            trace_result.all.return_value = []
            cost_result = MagicMock()
            cost_result.scalar.return_value = None
            pending_result = MagicMock()
            pending_result.scalar.return_value = 0

            db_session.execute.side_effect = [trace_result, cost_result, pending_result]

            app.dependency_overrides[get_current_user] = _current_user_override
            client = TestClient(app)
            response = client.get(
                "/api/overview",
                headers={"Authorization": "Bearer test-token"},
            )
            app.dependency_overrides.clear()

            assert response.status_code == 200
            data = response.json()
            assert data["total_calls"] == 0
            assert data["total_cost"] == 0

    def test_overview_with_traces(self):
        """Test overview endpoint with actual trace data."""
        with patch("server.lifespan.init_db"), patch("server.lifespan.seed_default_admin"):
            mock_db_session_local = AsyncMock()
            trace_data = [
                (TraceStatus.SUCCESS, 80),
                (TraceStatus.BLOCKED, 15),
                (TraceStatus.FAILED, 5),
            ]
            call_count = [0]

            def _mock_exec_side_effect(*_args, **_kwargs):
                result = MagicMock()
                if call_count[0] == 0:
                    result.all.return_value = trace_data
                elif call_count[0] == 1:
                    result.scalar.return_value = 25.75
                else:
                    result.scalar.return_value = 3
                call_count[0] += 1
                return result

            mock_db_session_local.execute.side_effect = _mock_exec_side_effect
            with _patch_async_session(mock_db_session_local):
                app.dependency_overrides[get_current_user] = _current_user_override
                client = TestClient(app)
                response = client.get(
                    "/api/overview",
                    headers={"Authorization": "Bearer test-token"},
                )
                app.dependency_overrides.clear()

            assert response.status_code == 200
            data = response.json()
            assert data["total_calls"] == 100
            assert data["success_rate"] == 80.0
            assert data["total_cost"] == 25.75

    def test_overview_handles_null_cost_named(self, db_session):
        """Test overview handles null cost."""
        with (
            patch("server.lifespan.init_db"),
            patch("server.lifespan.seed_default_admin"),
            _patch_async_session(db_session),
        ):
            call_count = [0]

            def _mock_exec_side_effect(*_args):
                result = MagicMock()
                if call_count[0] == 0:
                    result.all.return_value = []
                elif call_count[0] == 1:
                    result.scalar.return_value = None
                else:
                    result.scalar.return_value = 0
                call_count[0] += 1
                return result

            db_session.execute.side_effect = _mock_exec_side_effect

            app.dependency_overrides[get_current_user] = _current_user_override
            client = TestClient(app)
            response = client.get(
                "/api/overview",
                headers={"Authorization": "Bearer test-token"},
            )
            app.dependency_overrides.clear()
            assert response.json()["total_cost"] == 0


def test_system_info_set_on_startup() -> None:
    """System info must be registered for Prometheus metrics."""
    with (
        patch("server.lifespan.init_db"),
        patch("server.lifespan.seed_default_admin"),
        patch("server.metrics.system_info") as mock_system_info,
    ):
        importlib.reload(server.main)
        mock_system_info.info.assert_called()


def test_app_state_limiter_set() -> None:
    """App state must expose the configured limiter instance."""
    with patch("server.lifespan.init_db"), patch("server.lifespan.seed_default_admin"):
        assert app.state.limiter is limiter
