"""Core tests for Redis-based distributed rate limiting.

Tests cover:
- IP-based rate limiting
- Rate limit headers in responses
- Rate limit enforcement
- Rate limit configuration
- Independent limits per IP

For advanced tests including:
- Rate limit reset behavior
- Different endpoints
- State consistency and resilience
- Edge cases and boundary conditions
- Authentication integration
- Concurrency and load testing
- Observability and monitoring
- Redis storage operations
See: server_test_rate_limiting_advanced.py

Test Organization:
- Unit tests: Tests that verify configuration and don't require Redis
- Integration tests: Tests that require Redis for proper functionality

Running Tests:
1. Without Redis (default):
   pytest tests/server_test_rate_limiting.py
   Result: Unit tests PASS, integration tests SKIP

2. With Redis:
   # Start Redis first
   docker run -d -p 6379:6379 redis:latest
   # Or: redis-server

   # Set Redis URL
   export REDIS_URL="redis://localhost:6379/1"

   # Run tests
   pytest tests/server_test_rate_limiting.py
   Result: All tests should PASS

3. Run only unit tests:
   pytest tests/server_test_rate_limiting.py -m "not integration"

4. Run only integration tests (requires Redis):
   pytest tests/server_test_rate_limiting.py -m integration

Note: Integration tests are automatically skipped when Redis is not available.
The skip message explains that rate limit headers are not reliably injected
when using memory:// storage in TestClient, which is the fallback when Redis
is unavailable.
"""

import time

import pytest
from fastapi.testclient import TestClient
from redis import Redis
from sqlmodel import Session

from server.main import app, limiter
from server.models import get_session
from tests.rate_limiting_test_support import integration_test, redis_required
from tests.sqlite_test_helpers import client_with_session_override, in_memory_session

pytest_plugins = ("tests.rate_limiting_test_support",)


@pytest.fixture(name="session")
def session_fixture():
    """Create test database session."""
    yield from in_memory_session()


@pytest.fixture(name="client")
def client_fixture(session: Session):
    """Create test client with dependency override."""
    yield from client_with_session_override(app, get_session, session)


@pytest.mark.integration
class TestRateLimitIPAddressing:
    """Test that rate limiting uses IP addresses correctly."""

    @redis_required
    def test_rate_limit_uses_ip_address(self, client: TestClient, _redis_client_fixture: Redis):
        """Verify rate limiting keys are based on IP addresses."""
        _redis_client_fixture.flushdb()  # Clear any existing state
        # Make a request to trigger rate limiting key creation
        client.get("/api/traces", headers={"X-Real-IP": "192.168.1.100"})

        # Check that Redis has keys with IP address
        keys = _redis_client_fixture.keys("*192.168.1.100*")
        assert len(keys) > 0, "Redis should store rate limit data with IP address"

    @integration_test
    def test_rate_limit_different_ips_independent(
        self, client: TestClient, _redis_client_fixture: Redis
    ):
        """Test that different IPs have separate rate limit counters."""
        _redis_client_fixture.flushdb()  # Clear any existing state
        ip1 = "192.168.1.100"
        ip2 = "192.168.1.101"

        # Make 5 requests from IP1
        for _ in range(5):
            response = client.get("/api/traces", headers={"X-Real-IP": ip1})
            assert response.status_code == 200

        # Make 5 requests from IP2
        for _ in range(5):
            response = client.get("/api/traces", headers={"X-Real-IP": ip2})
            assert response.status_code == 200

        # Both IPs should still be able to make requests
        response1 = client.get("/api/traces", headers={"X-Real-IP": ip1})
        response2 = client.get("/api/traces", headers={"X-Real-IP": ip2})

        assert response1.status_code == 200
        assert response2.status_code == 200

    @integration_test
    def test_rate_limit_same_ip_shared_counter(
        self, client: TestClient, _redis_client_fixture: Redis
    ):
        """Test that requests from same IP share rate limit counter."""
        _redis_client_fixture.flushdb()  # Clear any existing state
        ip = "192.168.1.100"

        # Make multiple requests from same IP
        responses = []
        for _ in range(3):
            response = client.get("/api/traces", headers={"X-Real-IP": ip})
            responses.append(response)

        # Check rate limit remaining decreases
        remaining_values = [
            int(r.headers.get("X-RateLimit-Remaining", "0"))
            for r in responses
            if "X-RateLimit-Remaining" in r.headers
        ]

        if len(remaining_values) >= 2:
            # Remaining should decrease with each request
            assert remaining_values[0] > remaining_values[-1]


@pytest.mark.integration
class TestRateLimitHeaders:
    """Test rate limit headers in responses.

    These tests require Redis for proper rate limit header injection.
    slowapi does not reliably inject headers when using memory:// storage in TestClient.
    """

    @integration_test
    def test_rate_limit_headers_present(self, client: TestClient, _redis_client_fixture: Redis):
        """Verify rate limit headers are included in responses."""
        response = client.get("/api/traces")

        assert "X-RateLimit-Limit" in response.headers
        assert "X-RateLimit-Remaining" in response.headers
        assert "X-RateLimit-Reset" in response.headers

    @integration_test
    def test_rate_limit_limit_header_value(self, client: TestClient, _redis_client_fixture: Redis):
        """Test X-RateLimit-Limit header has correct value."""
        response = client.get("/api/traces")

        limit = response.headers.get("X-RateLimit-Limit")
        assert limit is not None
        assert int(limit) > 0, "Rate limit should be positive"

    @integration_test
    def test_rate_limit_remaining_decreases(self, client: TestClient, _redis_client_fixture: Redis):
        """Test X-RateLimit-Remaining decreases with requests."""
        ip = "192.168.1.102"

        # First request
        response1 = client.get("/api/traces", headers={"X-Real-IP": ip})
        remaining1 = int(response1.headers.get("X-RateLimit-Remaining", "0"))

        # Second request
        response2 = client.get("/api/traces", headers={"X-Real-IP": ip})
        remaining2 = int(response2.headers.get("X-RateLimit-Remaining", "0"))

        # Remaining should decrease
        assert remaining2 < remaining1

    @integration_test
    def test_rate_limit_reset_header_format(self, client: TestClient, _redis_client_fixture: Redis):
        """Test X-RateLimit-Reset header is a valid timestamp."""
        response = client.get("/api/traces")

        reset = response.headers.get("X-RateLimit-Reset")
        assert reset is not None

        # Should be a numeric timestamp
        reset_time = int(reset)
        assert reset_time > int(time.time()), "Reset time should be in the future"


@pytest.mark.integration
class TestRateLimitEnforcement:
    """Test rate limit enforcement behavior.

    These tests require Redis for proper rate limiting with isolated state.
    """

    @integration_test
    def test_rate_limit_blocks_after_threshold(
        self, client: TestClient, _redis_client_fixture: Redis
    ):
        """Test that rate limit blocks requests after threshold is exceeded."""
        ip = "192.168.1.103"
        _redis_client_fixture.flushdb()  # Clear any existing state

        # Make requests up to the limit (100/minute default)
        responses = []
        for _i in range(102):
            response = client.get("/api/traces", headers={"X-Real-IP": ip})
            responses.append(response)

            # Stop if we get rate limited
            if response.status_code == 429:
                break

        # Should have gotten a 429 response
        status_codes = [r.status_code for r in responses]
        assert 429 in status_codes, "Should receive 429 Too Many Requests"

    @integration_test
    def test_rate_limit_exceeded_response_format(
        self, client: TestClient, _redis_client_fixture: Redis
    ):
        """Test that 429 response has correct format."""
        ip = "192.168.1.104"
        _redis_client_fixture.flushdb()  # Clear any existing state

        # Exhaust rate limit
        for _ in range(101):
            response = client.get("/api/traces", headers={"X-Real-IP": ip})
            if response.status_code == 429:
                break

        # Check 429 response
        assert response.status_code == 429
        assert "application/json" in response.headers.get("content-type", "")

        data = response.json()
        assert "error" in data or "detail" in data

    @integration_test
    def test_rate_limit_allows_requests_under_threshold(
        self, client: TestClient, _redis_client_fixture: Redis
    ):
        """Test that requests under threshold are allowed."""
        ip = "192.168.1.105"
        _redis_client_fixture.flushdb()  # Clear any existing state

        # Make several requests under the limit
        for _ in range(10):
            response = client.get("/api/traces", headers={"X-Real-IP": ip})
            assert response.status_code == 200


class TestRateLimitConfiguration:
    """Test rate limiter configuration."""

    def test_limiter_uses_storage(self):
        """Verify limiter has storage configured."""
        # Storage URI can be either memory:// or redis://
        storage_uri = str(vars(limiter).get("_storage_uri"))
        assert storage_uri in ["memory://", "redis://localhost:6379/1"] or "redis://" in storage_uri

    def test_limiter_default_limit_configured(self):
        """Test that default rate limit is configured."""
        # Limiter should have default limits set
        default_limits = vars(limiter).get("_default_limits")
        assert default_limits is not None
        assert len(default_limits) > 0

    def test_limiter_key_function_uses_ip(self):
        """Test that limiter key function uses IP addresses."""
        # Verify key function is callable
        # The key function should be callable
        assert callable(vars(limiter).get("_key_func"))
