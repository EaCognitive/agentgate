"""Router-focused tests for OAuth2 device authorization flow endpoints."""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import User
from server.routers import device_auth
from tests.router_test_support import bearer_headers, create_test_user

pytest_plugins = ("tests.router_test_support",)

def _fake_login_result() -> SimpleNamespace:
    """Return the minimal login result shape used by device auth token exchange."""
    return SimpleNamespace(
        access_token="device-access-token",
        refresh_token="device-refresh-token",
        expires_in=900,
    )


def _device_code_store() -> dict[str, object]:
    """Return the in-memory device code store used by the device auth router."""
    return getattr(device_auth, "_device_codes")


@pytest.fixture(scope="function", autouse=True)
def clear_device_code_store() -> None:
    """Reset in-memory device code store between tests."""
    _device_code_store().clear()
    try:
        yield
    finally:
        _device_code_store().clear()


@pytest.fixture(name="user")
def user_fixture(session: Session) -> User:
    """Create test user for device authorization approval."""
    return create_test_user(
        session,
        email="device-auth@test.com",
        name="Device Auth",
        password="Password123!",
        role="admin",
        is_active=True,
    )


@pytest.fixture(name="auth_headers")
def auth_headers_fixture(user: User) -> dict[str, str]:
    """Return bearer token headers for device approval endpoints."""
    return bearer_headers(
        user,
        expires_delta=timedelta(minutes=15),
    )


def test_request_device_code_returns_rfc8628_shape(client: TestClient) -> None:
    """`/code` endpoint should return polling metadata and verification URLs."""
    response = client.post(
        "/api/auth/device/code",
        json={"client_id": "mcp-test", "scope": "full_access"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["device_code"]
    assert payload["user_code"]
    assert payload["verification_uri"].endswith("/login")
    assert "device_code=" in payload["verification_uri_complete"]
    assert payload["interval"] >= 1
    assert payload["expires_in"] >= 60


def test_poll_device_token_pending_before_authorization(client: TestClient) -> None:
    """Polling token endpoint before user approval should return pending error."""
    code_response = client.post(
        "/api/auth/device/code",
        json={"client_id": "mcp-test", "scope": "full_access"},
    )
    device_code = code_response.json()["device_code"]

    response = client.post(
        "/api/auth/device/token",
        json={"device_code": device_code},
    )

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["error"] == "authorization_pending"


def test_authorize_then_poll_returns_tokens(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    auth_headers: dict[str, str],
) -> None:
    """Authorized device code should exchange for access and refresh tokens."""

    async def _fake_complete_login(**_kwargs):
        return _fake_login_result()

    monkeypatch.setattr(device_auth, "complete_login", _fake_complete_login)

    code_response = client.post(
        "/api/auth/device/code",
        json={"client_id": "mcp-test", "scope": "full_access"},
    )
    code_payload = code_response.json()

    authorize_response = client.post(
        "/api/auth/device/authorize",
        headers=auth_headers,
        json={"user_code": code_payload["user_code"]},
    )
    assert authorize_response.status_code == 200

    token_response = client.post(
        "/api/auth/device/token",
        json={"device_code": code_payload["device_code"]},
    )

    assert token_response.status_code == 200
    token_payload = token_response.json()
    assert token_payload["access_token"] == "device-access-token"
    assert token_payload["refresh_token"] == "device-refresh-token"
    assert token_payload["token_type"] == "bearer"
    assert token_payload["user"]["email"] == "device-auth@test.com"


def test_deny_device_sets_access_denied_state(
    client: TestClient,
    auth_headers: dict[str, str],
) -> None:
    """Denied device flow should return `access_denied` on token polling."""
    code_response = client.post(
        "/api/auth/device/code",
        json={"client_id": "mcp-test", "scope": "full_access"},
    )
    code_payload = code_response.json()

    deny_response = client.post(
        "/api/auth/device/deny",
        headers=auth_headers,
        json={"user_code": code_payload["user_code"]},
    )
    assert deny_response.status_code == 200

    token_response = client.post(
        "/api/auth/device/token",
        json={"device_code": code_payload["device_code"]},
    )

    assert token_response.status_code == 400
    detail = token_response.json()["detail"]
    assert detail["error"] == "access_denied"


def test_device_status_invalid_code_returns_invalid(client: TestClient) -> None:
    """Status endpoint should report invalid for unknown user codes."""
    response = client.get("/api/auth/device/status/DOES-NOT-EXIST")

    assert response.status_code == 200
    payload = response.json()
    assert payload["valid"] is False
