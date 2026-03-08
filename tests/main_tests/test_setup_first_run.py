"""Tests for first-run setup constraints and API key timestamp handling."""

from __future__ import annotations

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

from server.routers import setup as setup_router_module
from server.routers.api_keys import APIKey
from server.routers.setup import _enforce_browser_setup_request


def _make_request(*, origin: str | None = None, referer: str | None = None) -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if origin is not None:
        headers.append((b"origin", origin.encode("utf-8")))
    if referer is not None:
        headers.append((b"referer", referer.encode("utf-8")))

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "path": "/api/setup/complete",
        "raw_path": b"/api/setup/complete",
        "query_string": b"",
        "headers": headers,
        "client": ("127.0.0.1", 12345),
        "server": ("localhost", 8000),
        "scheme": "http",
    }
    return Request(scope)


def test_enforce_browser_setup_request_accepts_allowed_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Setup completion accepts requests from allowed dashboard origin."""
    monkeypatch.setattr(
        "server.routers.setup.get_allowed_origins",
        lambda: ["http://localhost:3000"],
    )

    request = _make_request(origin="http://localhost:3000")
    _enforce_browser_setup_request(request)


def test_enforce_browser_setup_request_accepts_referer_when_origin_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Setup completion accepts valid dashboard referer fallback."""
    monkeypatch.setattr(
        "server.routers.setup.get_allowed_origins",
        lambda: ["http://localhost:3000"],
    )

    request = _make_request(referer="http://localhost:3000/setup")
    _enforce_browser_setup_request(request)


def test_enforce_browser_setup_request_rejects_non_browser_flow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Setup completion rejects requests without allowed browser origin."""
    monkeypatch.setattr(
        "server.routers.setup.get_allowed_origins",
        lambda: ["http://localhost:3000"],
    )

    request = _make_request()
    with pytest.raises(HTTPException) as exc_info:
        _enforce_browser_setup_request(request)

    assert exc_info.value.status_code == 403


def test_enforce_browser_setup_request_accepts_dashboard_env_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Setup completion accepts configured dashboard origin from environment."""
    monkeypatch.setattr(
        "server.routers.setup.get_allowed_origins",
        lambda: [],
    )
    monkeypatch.setenv("AGENTGATE_DASHBOARD_URL", "http://localhost:3000")

    request = _make_request(origin="http://localhost:3000")
    _enforce_browser_setup_request(request)


def test_enforce_browser_setup_request_accepts_loopback_host_equivalence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Setup completion accepts localhost/127.0.0.1 host-equivalent loopback origins."""
    monkeypatch.setattr(
        "server.routers.setup.get_allowed_origins",
        lambda: ["http://localhost:3000"],
    )

    request = _make_request(origin="http://127.0.0.1:3000")
    _enforce_browser_setup_request(request)


def test_api_key_created_at_is_naive_datetime() -> None:
    """API keys use timezone-naive datetimes for TIMESTAMP WITHOUT TIME ZONE columns."""
    api_key = APIKey(
        name="test",
        key_hash="hash",
        key_prefix="ag_test_key",
        user_id=1,
        scopes="*",
    )

    created_at = api_key.created_at
    assert getattr(created_at, "tzinfo", None) is None


class _FakeResult:
    """Emulate SQLAlchemy result for setup test fakes."""

    def __init__(self, existing):
        self._existing = existing

    def scalars(self):
        """Return self to emulate SQLAlchemy scalar result access."""
        return self

    def first(self):
        """Return first record from the emulated result set."""
        return self._existing


class _FakeSessionWithTracking:
    """Emulate SQLAlchemy async session with add-tracking for flush."""

    def __init__(self):
        self._last_added = None

    def add(self, _obj) -> None:
        """Emulate AsyncSession.add without side effects."""
        self._last_added = _obj

    def last_added(self):
        """Return the most recently added object."""
        return self._last_added


async def _fake_get_session_with_tracking():
    """Yield a fake session with add-tracking for dependency override."""
    yield _FakeSessionWithTracking()


async def _fake_execute(_session, _statement):
    """Return empty result set for setup queries."""
    return _FakeResult(None)


async def _fake_commit(_session):
    """No-op commit."""
    return None


async def _fake_flush(session):
    """Emulate flush by assigning id to last added object."""
    last_added = session.last_added()
    if last_added is not None:
        last_added.id = 1


async def _fake_rollback(_session):
    """No-op rollback."""
    return None


async def _fake_refresh(_session, obj):
    """Emulate refresh by setting id on object."""
    obj.id = 1
    return None


async def _fake_emit_audit_event(*_args, **_kwargs):
    """No-op audit event emitter."""
    return None


async def _fake_is_setup_required_true() -> bool:
    """Return True to indicate setup is needed."""
    return True


def test_setup_complete_accepts_json_body_with_browser_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Setup completion accepts JSON request body and succeeds in browser flow."""
    monkeypatch.setattr(
        setup_router_module,
        "get_allowed_origins",
        lambda: ["http://localhost:3000"],
    )
    monkeypatch.setattr(setup_router_module, "db_execute", _fake_execute)
    monkeypatch.setattr(setup_router_module, "db_commit", _fake_commit)
    monkeypatch.setattr(setup_router_module, "db_flush", _fake_flush)
    monkeypatch.setattr(setup_router_module, "db_rollback", _fake_rollback)
    monkeypatch.setattr(setup_router_module, "db_refresh", _fake_refresh)
    monkeypatch.setattr(setup_router_module, "emit_audit_event", _fake_emit_audit_event)
    monkeypatch.setattr(setup_router_module, "mark_setup_complete", lambda: None)
    monkeypatch.setattr(
        setup_router_module,
        "is_setup_required",
        _fake_is_setup_required_true,
    )

    app = FastAPI()
    app.include_router(setup_router_module.router, prefix="/api")
    app.dependency_overrides[setup_router_module.get_session] = _fake_get_session_with_tracking

    client = TestClient(app)
    response = client.post(
        "/api/setup/complete",
        headers={"Origin": "http://localhost:3000"},
        json={
            "email": "first.admin@example.com",
            "password": "StrongPass!1234",
            "name": "First Admin",
            "generate_api_key": False,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    assert payload["email"] == "first.admin@example.com"


def test_setup_complete_rejects_when_setup_window_is_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Setup completion rejects requests when runtime setup state is already closed."""

    class _FakeResult:
        """Emulate SQLAlchemy result for setup-closed tests."""

        def __init__(self, existing):
            self._existing = existing

        def scalars(self):
            """Return self to emulate SQLAlchemy scalar result access."""
            return self

        def first(self):
            """Return first record from the emulated result set."""
            return self._existing

    class _FakeSession:
        """Minimal session stub for setup-closed tests."""

        def add(self, _obj) -> None:
            """Emulate AsyncSession.add without side effects."""

        def close(self) -> None:
            """Emulate session close."""

    async def _fake_get_session():
        yield _FakeSession()

    async def _fake_execute(_session, _statement):
        """Return empty result set for setup-closed queries."""
        return _FakeResult(None)

    monkeypatch.setattr(
        setup_router_module,
        "get_allowed_origins",
        lambda: ["http://localhost:3000"],
    )
    monkeypatch.setattr(setup_router_module, "db_execute", _fake_execute)

    async def _fake_is_setup_required() -> bool:
        """Return False to simulate a closed setup window."""
        return False

    monkeypatch.setattr(setup_router_module, "is_setup_required", _fake_is_setup_required)

    app = FastAPI()
    app.include_router(setup_router_module.router, prefix="/api")
    app.dependency_overrides[setup_router_module.get_session] = _fake_get_session

    client = TestClient(app)
    response = client.post(
        "/api/setup/complete",
        headers={"Origin": "http://localhost:3000"},
        json={
            "email": "first.admin@example.com",
            "password": "StrongPass!1234",
            "name": "First Admin",
            "generate_api_key": False,
        },
    )

    assert response.status_code == 409
    assert "Setup already completed" in response.json()["detail"]


def test_setup_complete_fails_when_required_tables_are_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Setup completion returns 503 when required schema tables are absent."""

    class _FakeResult:
        """Emulate SQLAlchemy result for missing-table tests."""

        def __init__(self, existing):
            self._existing = existing

        def scalars(self):
            """Return self to emulate SQLAlchemy scalar result access."""
            return self

        def first(self):
            """Return first record from the emulated result set."""
            return self._existing

    class _FakeSession:
        """Minimal session stub for missing-table tests."""

        def add(self, _obj) -> None:
            """Emulate AsyncSession.add without side effects."""

        def close(self) -> None:
            """Emulate session close."""

    async def _fake_get_session():
        """Yield a fake session for dependency overrides."""
        yield _FakeSession()

    async def _fake_execute(_session, _statement):
        """Return empty result set for setup queries."""
        return _FakeResult(None)

    async def _fake_is_setup_required() -> bool:
        """Return True to indicate setup is still required."""
        return True

    async def _fake_find_missing_tables(_session, _required_tables):
        """Return a deterministic missing-table list."""
        return ["api_keys", "audit_log"]

    monkeypatch.setattr(
        setup_router_module,
        "get_allowed_origins",
        lambda: ["http://localhost:3000"],
    )
    monkeypatch.setattr(setup_router_module, "db_execute", _fake_execute)
    monkeypatch.setattr(setup_router_module, "is_setup_required", _fake_is_setup_required)
    monkeypatch.setattr(
        setup_router_module,
        "_find_missing_setup_tables",
        _fake_find_missing_tables,
    )

    app = FastAPI()
    app.include_router(setup_router_module.router, prefix="/api")
    app.dependency_overrides[setup_router_module.get_session] = _fake_get_session

    client = TestClient(app)
    response = client.post(
        "/api/setup/complete",
        headers={"Origin": "http://localhost:3000"},
        json={
            "email": "first.admin@example.com",
            "password": "StrongPass!1234",
            "name": "First Admin",
            "generate_api_key": True,
        },
    )

    assert response.status_code == 503
    detail = response.json()["detail"]
    assert detail["error"] == "setup_prerequisite_tables_missing"
    assert detail["missing_tables"] == ["api_keys", "audit_log"]
