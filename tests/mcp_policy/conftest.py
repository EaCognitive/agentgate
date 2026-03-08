"""Shared fixtures for MCP policy-governance integration tests."""

from __future__ import annotations

from collections.abc import AsyncGenerator

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from server.mcp.api_client import MCPApiClient, _ClientState
from server.models import get_session
from server.routers import (
    auth_router,
    policies_router,
    policy_governance_router,
    settings_router,
)


@pytest.fixture
async def mcp_local_client(
    async_session,
    admin_headers,
) -> AsyncGenerator[tuple[MCPApiClient, list[str]], None]:
    """Create an in-process MCP API client bound to test routers."""
    app = FastAPI(title="mcp-policy-test-app")
    app.include_router(auth_router, prefix="/api")
    app.include_router(policies_router, prefix="/api")
    app.include_router(settings_router, prefix="/api")
    app.include_router(policy_governance_router, prefix="/api")

    async def _session_override():
        return async_session

    app.dependency_overrides[get_session] = _session_override

    requested_paths: list[str] = []

    async def _record_request(request):
        requested_paths.append(request.url.path)

    transport = ASGITransport(app=app)
    http_client = AsyncClient(
        transport=transport,
        base_url="http://localhost",
        event_hooks={"request": [_record_request]},
    )

    client = MCPApiClient(base_url="http://localhost")
    client._client = http_client  # pylint: disable=protected-access
    client.token = admin_headers["Authorization"].split(" ", 1)[1]
    previous_singleton = _ClientState.instance
    _ClientState.instance = client

    yield client, requested_paths

    _ClientState.instance = previous_singleton
    await http_client.aclose()
    app.dependency_overrides.clear()
