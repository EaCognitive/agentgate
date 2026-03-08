"""Regression tests for auth rate-limit behavior in test mode."""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient


pytestmark = pytest.mark.integration


def _build_user_payload() -> dict[str, str]:
    """Create unique registration payload for each test invocation."""
    suffix = uuid.uuid4().hex[:10]
    return {
        "email": f"rate-limit-{suffix}@example.com",
        "password": "SecurePass123!",
        "name": "Rate Limit Test User",
    }


def test_register_does_not_use_production_rate_limit_in_test_mode(
    client: TestClient,
) -> None:
    """Register endpoint must not return 429s while TESTING mode is enabled."""
    responses = []
    for _ in range(8):
        payload = _build_user_payload()
        responses.append(client.post("/api/auth/register", json=payload))

    throttled = [response for response in responses if response.status_code == 429]
    assert not throttled


def test_login_does_not_use_production_rate_limit_in_test_mode(
    client: TestClient,
) -> None:
    """Login endpoint must keep test-mode limits relaxed across repeated calls."""
    payload = _build_user_payload()
    register = client.post("/api/auth/register", json=payload)
    assert register.status_code == 200, register.text

    responses = []
    for _ in range(8):
        responses.append(
            client.post(
                "/api/auth/login",
                json={
                    "email": payload["email"],
                    "password": payload["password"],
                },
            )
        )

    throttled = [response for response in responses if response.status_code == 429]
    assert not throttled
