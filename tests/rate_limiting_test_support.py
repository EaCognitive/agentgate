"""Shared helpers for rate-limiting tests."""

from __future__ import annotations

import os
from collections.abc import Generator

import pytest
from redis import Redis
from redis.exceptions import RedisError
from slowapi import Limiter
from slowapi.util import get_ipaddr


def is_redis_available() -> bool:
    """Check if Redis is available for testing."""
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/1")
    try:
        client = Redis.from_url(redis_url, decode_responses=True)
        client.ping()
        client.close()
        return True
    except (OSError, RedisError):
        return False


redis_required = pytest.mark.skipif(
    not is_redis_available(),
    reason="Redis is not available. Start Redis or set REDIS_URL environment variable.",
)

integration_test = pytest.mark.skipif(
    not is_redis_available(),
    reason="Integration test requires Redis for proper rate limiter functionality. "
    "Rate limit headers are not reliably injected when using memory:// storage in tests.",
)


@pytest.fixture(name="_redis_client_fixture")
def redis_client_fixture() -> Generator[Redis, None, None]:
    """Create and clean a Redis client dedicated to the rate-limit test DB."""
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/1")
    client = Redis.from_url(redis_url, decode_responses=True)
    client.flushdb()
    try:
        yield client
    finally:
        client.flushdb()
        client.close()


@pytest.fixture(name="test_limiter")
def test_limiter_fixture(_redis_client_fixture: Redis) -> Limiter:
    """Create a limiter instance bound to the test Redis DB."""
    return Limiter(
        key_func=get_ipaddr,
        storage_uri=os.getenv("REDIS_URL", "redis://localhost:6379/1"),
        strategy="moving-window",
        default_limits=["10/minute"],
    )
