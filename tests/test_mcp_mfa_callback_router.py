"""Router-focused tests for MCP Azure AD MFA callback endpoint."""

from __future__ import annotations

import sys
import types
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from server.main import app
from server.routers import mcp_mfa_callback

def _verify_result(
    *,
    verified: bool,
    message: str = "ok",
    hint: str | None = None,
) -> SimpleNamespace:
    """Return the minimal result object returned by verify_mfa_completion."""
    return SimpleNamespace(verified=verified, message=message, hint=hint)


@pytest.fixture(name="client")
def client_fixture() -> TestClient:
    """Create simple TestClient for callback route checks."""
    return TestClient(app)


@pytest.fixture(scope="function", autouse=True)
def patch_audit_dependencies(monkeypatch: pytest.MonkeyPatch):
    """Patch audit/session dependencies so callback tests stay isolated."""

    @asynccontextmanager
    async def _fake_session_context():
        yield object()

    async def _fake_emit_audit_event(*_args, **_kwargs):
        return None

    monkeypatch.setattr(
        mcp_mfa_callback,
        "get_session_context",
        _fake_session_context,
    )
    monkeypatch.setattr(
        mcp_mfa_callback,
        "emit_audit_event",
        _fake_emit_audit_event,
    )


def test_mfa_callback_returns_error_page_for_azure_error(client: TestClient) -> None:
    """Azure callback errors should render the explicit failure page."""
    response = client.get(
        "/api/auth/mfa-callback?error=access_denied&error_description=User%20cancelled",
    )

    assert response.status_code == 400
    assert "MFA Verification Failed" in response.text
    assert "access_denied" in response.text


def test_mfa_callback_rejects_missing_required_params(client: TestClient) -> None:
    """Missing code or state should fail with a clear validation page."""
    response = client.get("/api/auth/mfa-callback")

    assert response.status_code == 400
    assert "Missing required parameters" in response.text


def test_mfa_callback_rejects_invalid_state_format(client: TestClient) -> None:
    """State must contain the challenge-id prefix and separator token."""
    response = client.get("/api/auth/mfa-callback?code=abc123&state=invalid")

    assert response.status_code == 400
    assert "Invalid state format" in response.text


def test_mfa_callback_success_page_contains_challenge_id(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verified callback should render success page with challenge instructions."""

    fake_module = types.ModuleType("server.mcp.azure_mfa_guard")

    async def _fake_verify_mfa_completion(*_args, **_kwargs):
        return _verify_result(verified=True)

    fake_module.verify_mfa_completion = _fake_verify_mfa_completion
    monkeypatch.setitem(sys.modules, "server.mcp.azure_mfa_guard", fake_module)

    response = client.get(
        "/api/auth/mfa-callback?code=good-code&state=challenge123:state-suffix",
    )

    assert response.status_code == 200
    assert "MFA Verification Complete" in response.text
    assert "challenge123" in response.text


def test_mfa_callback_verification_failure_renders_error(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verification failures should render a descriptive error page."""

    fake_module = types.ModuleType("server.mcp.azure_mfa_guard")

    async def _fake_verify_mfa_completion(*_args, **_kwargs):
        return _verify_result(
            verified=False,
            message="MFA challenge expired",
            hint="Generate a new challenge",
        )

    fake_module.verify_mfa_completion = _fake_verify_mfa_completion
    monkeypatch.setitem(sys.modules, "server.mcp.azure_mfa_guard", fake_module)

    response = client.get(
        "/api/auth/mfa-callback?code=expired-code&state=challenge999:state-suffix",
    )

    assert response.status_code == 400
    assert "MFA challenge expired" in response.text
    assert "Generate a new challenge" in response.text
