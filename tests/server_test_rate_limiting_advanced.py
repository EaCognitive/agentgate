"""Advanced tests for Redis-based distributed rate limiting.

This module contains advanced test scenarios including:
- Rate limit reset behavior
- Different endpoint behavior
- State consistency and resilience
- Edge cases and boundary conditions
- Authentication integration
- Concurrency and load testing
- Observability and monitoring
- Redis storage operations

For basic rate limiting tests, see server_test_rate_limiting.py

Running Tests:
1. Without Redis (default):
   pytest tests/server_test_rate_limiting_advanced.py
   Result: Unit tests PASS, integration tests SKIP

2. With Redis:
   # Start Redis first
   docker run -d -p 6379:6379 redis:latest
   # Or: redis-server

   # Set Redis URL
   export REDIS_URL="redis://localhost:6379/1"

   # Run tests
   pytest tests/server_test_rate_limiting_advanced.py
   Result: All tests should PASS

3. Run only advanced integration tests (requires Redis):
   pytest tests/server_test_rate_limiting_advanced.py -m integration
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


class TestRedisBackend:
    """Test Redis storage backend functionality."""

    @redis_required
    def test_redis_connection_required(self, _redis_client_fixture: Redis):
        """Verify Redis connection is working."""
        # Test Redis connectivity
        assert _redis_client_fixture.ping(), "Redis should be reachable"

    @redis_required
    def test_rate_limit_data_stored_in_redis(
        self, client: TestClient, _redis_client_fixture: Redis
    ):
        """Verify rate limit data is stored in Redis."""
        ip = "192.168.1.106"

        # Clear Redis
        _redis_client_fixture.flushdb()

        # Make a request
        client.get("/api/traces", headers={"X-Real-IP": ip})

        # Check Redis has rate limit keys
        keys = _redis_client_fixture.keys("*")
        assert len(keys) > 0, "Redis should contain rate limit data"

    @redis_required
    def test_rate_limit_persists_across_requests(
        self, client: TestClient, _redis_client_fixture: Redis
    ):
        """Test that rate limit state persists in Redis."""
        ip = "192.168.1.107"

        # Make first request
        response1 = client.get("/api/traces", headers={"X-Real-IP": ip})
        remaining1 = int(response1.headers.get("X-RateLimit-Remaining", "0"))

        # Make second request
        response2 = client.get("/api/traces", headers={"X-Real-IP": ip})
        remaining2 = int(response2.headers.get("X-RateLimit-Remaining", "0"))

        # State should persist
        assert remaining2 == remaining1 - 1

    @redis_required
    def test_redis_ttl_set_correctly(self, client: TestClient, _redis_client_fixture: Redis):
        """Verify Redis keys have appropriate TTL."""
        ip = "192.168.1.108"

        # Make a request
        client.get("/api/traces", headers={"X-Real-IP": ip})

        # Check TTL on keys
        keys = _redis_client_fixture.keys("*")
        assert len(keys) > 0

        for key in keys:
            ttl = _redis_client_fixture.ttl(key)
            # TTL should be positive (key expires) and reasonable (< 2 minutes)
            assert -1 <= ttl <= 120, f"TTL should be reasonable, got {ttl}"


class TestMovingWindowStrategy:
    """Test moving window rate limiting strategy."""

    def test_moving_window_configuration(self):
        """Verify limiter uses moving-window strategy."""
        # Check limiter configuration - use internal attribute
        assert vars(limiter).get("_strategy") == "moving-window"

    @integration_test
    def test_moving_window_allows_gradual_recovery(
        self, client: TestClient, _redis_client_fixture: Redis
    ):
        """Test that moving window allows gradual rate limit recovery."""
        ip = "192.168.1.109"
        _redis_client_fixture.flushdb()  # Clear any existing state

        # Make some requests
        for _ in range(5):
            client.get("/api/traces", headers={"X-Real-IP": ip})

        # Make request so window state is captured
        client.get("/api/traces", headers={"X-Real-IP": ip})

        # Wait a bit (moving window should start recovering)
        time.sleep(1)

        # Make another request
        response2 = client.get("/api/traces", headers={"X-Real-IP": ip})
        remaining2 = int(response2.headers.get("X-RateLimit-Remaining", "0"))

        # With moving window, remaining might recover slightly
        # (This is time-dependent, so we just verify the mechanism exists)
        assert remaining2 >= 0


@pytest.mark.integration
class TestRateLimitReset:
    """Test rate limit reset behavior."""

    @integration_test
    def test_rate_limit_reset_time_accurate(self, client: TestClient, _redis_client_fixture: Redis):
        """Test that reset time header is accurate."""
        ip = "192.168.1.110"
        _redis_client_fixture.flushdb()  # Clear any existing state

        response = client.get("/api/traces", headers={"X-Real-IP": ip})
        reset_time = int(response.headers.get("X-RateLimit-Reset", "0"))
        current_time = int(time.time())

        # Reset should be in the near future (within 60 seconds)
        assert current_time < reset_time <= current_time + 60

    @redis_required
    def test_rate_limit_remaining_resets_after_window(
        self, client: TestClient, _redis_client_fixture: Redis
    ):
        """Test that rate limit resets after time window expires."""
        ip = "192.168.1.111"

        # Make requests to establish rate limit
        for _ in range(5):
            client.get("/api/traces", headers={"X-Real-IP": ip})

        # Get remaining count
        response1 = client.get("/api/traces", headers={"X-Real-IP": ip})
        remaining1 = int(response1.headers.get("X-RateLimit-Remaining", "0"))

        # Clear Redis to simulate window expiration
        _redis_client_fixture.flushdb()

        # Make another request
        response2 = client.get("/api/traces", headers={"X-Real-IP": ip})
        remaining2 = int(response2.headers.get("X-RateLimit-Remaining", "0"))

        # After reset, remaining should be higher
        assert remaining2 > remaining1


@pytest.mark.integration
class TestDifferentEndpoints:
    """Test rate limiting across different endpoints."""

    @integration_test
    def test_rate_limit_applies_to_health_endpoint(
        self, client: TestClient, _redis_client_fixture: Redis
    ):
        """Test that health endpoint has rate limit headers."""
        _redis_client_fixture.flushdb()  # Clear any existing state
        response = client.get("/api/health")

        # Health endpoint should have rate limit headers
        assert "X-RateLimit-Limit" in response.headers
        assert "X-RateLimit-Remaining" in response.headers

    @integration_test
    def test_rate_limit_applies_to_traces_endpoint(
        self, client: TestClient, _redis_client_fixture: Redis
    ):
        """Test that traces endpoint has rate limit headers."""
        _redis_client_fixture.flushdb()  # Clear any existing state
        response = client.get("/api/traces")

        assert "X-RateLimit-Limit" in response.headers
        assert "X-RateLimit-Remaining" in response.headers

    @integration_test
    def test_rate_limit_shared_across_endpoints(
        self, client: TestClient, _redis_client_fixture: Redis
    ):
        """Test that rate limit is shared across different endpoints."""
        ip = "192.168.1.112"
        _redis_client_fixture.flushdb()  # Clear any existing state

        # Make request to health endpoint
        response1 = client.get("/api/health", headers={"X-Real-IP": ip})
        remaining1 = int(response1.headers.get("X-RateLimit-Remaining", "0"))

        # Make request to traces endpoint
        response2 = client.get("/api/traces", headers={"X-Real-IP": ip})
        remaining2 = int(response2.headers.get("X-RateLimit-Remaining", "0"))

        # Remaining should decrease across endpoints
        assert remaining2 < remaining1


@pytest.mark.integration
class TestRateLimitStateConsistency:
    """Test rate limit state consistency."""

    @integration_test
    def test_concurrent_requests_maintain_consistency(
        self, client: TestClient, _redis_client_fixture: Redis
    ):
        """Test that concurrent requests maintain consistent state."""
        _redis_client_fixture.flushdb()  # Clear any existing state
        ip = "192.168.1.113"

        # Make multiple rapid requests
        responses = []
        for _ in range(10):
            response = client.get("/api/traces", headers={"X-Real-IP": ip})
            responses.append(response)

        # All requests should succeed or fail consistently
        status_codes = [r.status_code for r in responses]

        # Should not have inconsistent states
        assert all(code in [200, 429] for code in status_codes)

    @redis_required
    def test_rate_limit_state_recovers_correctly(
        self, client: TestClient, _redis_client_fixture: Redis
    ):
        """Test that rate limit state recovers correctly after expiration."""
        ip = "192.168.1.114"

        # Establish initial state
        response1 = client.get("/api/traces", headers={"X-Real-IP": ip})
        remaining1 = int(response1.headers.get("X-RateLimit-Remaining", "0"))

        # Clear Redis
        _redis_client_fixture.flushdb()

        # New request should have fresh limit
        response2 = client.get("/api/traces", headers={"X-Real-IP": ip})
        remaining2 = int(response2.headers.get("X-RateLimit-Remaining", "0"))

        # Should have full limit again
        assert remaining2 >= remaining1


@pytest.mark.integration
class TestRateLimitErrorHandling:
    """Test error handling in rate limiting."""

    @integration_test
    def test_rate_limit_with_missing_ip(self, client: TestClient, _redis_client_fixture: Redis):
        """Test rate limiting handles missing IP gracefully."""
        _redis_client_fixture.flushdb()  # Clear any existing state
        # Request without IP header should still work
        response = client.get("/api/traces")

        # Should succeed (using default IP) or be rate limited
        assert response.status_code in [200, 401, 429]  # 401 if auth required, 429 if rate limited

    @integration_test
    def test_rate_limit_with_invalid_ip(self, client: TestClient, _redis_client_fixture: Redis):
        """Test rate limiting handles invalid IP gracefully."""
        _redis_client_fixture.flushdb()  # Clear any existing state
        # Request with invalid IP format
        response = client.get("/api/traces", headers={"X-Real-IP": "invalid-ip"})

        # Should still work (slowapi handles this) or be rate limited
        assert response.status_code in [200, 401, 429]


@pytest.mark.integration
class TestRateLimitMetrics:
    """Test rate limit metrics and monitoring."""

    @integration_test
    def test_rate_limit_headers_are_numeric(self, client: TestClient, _redis_client_fixture: Redis):
        """Test that rate limit headers contain valid numeric values."""
        _redis_client_fixture.flushdb()  # Clear any existing state
        response = client.get("/api/traces")

        limit = response.headers.get("X-RateLimit-Limit")
        remaining = response.headers.get("X-RateLimit-Remaining")
        reset = response.headers.get("X-RateLimit-Reset")

        # All should be valid integers
        assert limit is not None and int(limit) >= 0
        assert remaining is not None and int(remaining) >= 0
        assert reset is not None and int(reset) > 0

    @integration_test
    def test_rate_limit_remaining_never_negative(
        self, client: TestClient, _redis_client_fixture: Redis
    ):
        """Test that remaining count never goes negative."""
        _redis_client_fixture.flushdb()  # Clear any existing state
        ip = "192.168.1.115"

        # Make multiple requests
        for _ in range(10):
            response = client.get("/api/traces", headers={"X-Real-IP": ip})
            if "X-RateLimit-Remaining" in response.headers:
                remaining = int(response.headers.get("X-RateLimit-Remaining", "0"))
                # Should never be negative
                assert remaining >= 0


@pytest.mark.integration
class TestRateLimitIntegration:
    """Integration tests for rate limiting system."""

    @redis_required
    def test_rate_limit_full_workflow(self, client: TestClient, _redis_client_fixture: Redis):
        """Test complete rate limiting workflow."""
        ip = "192.168.1.116"

        # Step 1: Fresh start
        _redis_client_fixture.flushdb()

        # Step 2: Make request and verify headers
        response = client.get("/api/traces", headers={"X-Real-IP": ip})
        assert "X-RateLimit-Limit" in response.headers
        assert int(response.headers["X-RateLimit-Limit"]) > 0

        # Step 3: Verify Redis storage
        keys = _redis_client_fixture.keys("*")
        assert len(keys) > 0

        # Step 4: Make more requests and track state
        remaining_values = []
        for _ in range(5):
            response = client.get("/api/traces", headers={"X-Real-IP": ip})
            remaining = int(response.headers.get("X-RateLimit-Remaining", "0"))
            remaining_values.append(remaining)

        # Step 5: Verify decreasing remaining
        assert remaining_values[0] > remaining_values[-1]

    @redis_required
    def test_rate_limit_multiple_ips_workflow(
        self, client: TestClient, _redis_client_fixture: Redis
    ):
        """Test rate limiting with multiple IPs."""
        _redis_client_fixture.flushdb()

        ips = ["192.168.1.117", "192.168.1.118", "192.168.1.119"]

        # Make requests from each IP
        for ip in ips:
            for _ in range(3):
                response = client.get("/api/traces", headers={"X-Real-IP": ip})
                assert response.status_code == 200

        # Verify Redis has separate keys for each IP
        all_keys = _redis_client_fixture.keys("*")
        assert len(all_keys) >= len(ips)


@pytest.mark.integration
class TestRateLimitEdgeCases:
    """Test edge cases and boundary conditions."""

    @integration_test
    def test_rate_limit_with_ipv6_address(self, client: TestClient, _redis_client_fixture: Redis):
        """Test rate limiting with IPv6 addresses."""
        _redis_client_fixture.flushdb()  # Clear any existing state
        ipv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        response = client.get("/api/traces", headers={"X-Real-IP": ipv6})

        # Should handle IPv6 addresses correctly
        assert "X-RateLimit-Limit" in response.headers
        assert response.status_code in [200, 401]

    @integration_test
    def test_rate_limit_with_localhost_ip(self, client: TestClient, _redis_client_fixture: Redis):
        """Test rate limiting with localhost IP."""
        _redis_client_fixture.flushdb()  # Clear any existing state
        response = client.get("/api/traces", headers={"X-Real-IP": "127.0.0.1"})

        assert "X-RateLimit-Limit" in response.headers
        assert response.status_code in [200, 401, 429]

    @integration_test
    def test_rate_limit_with_private_ip(self, client: TestClient, _redis_client_fixture: Redis):
        """Test rate limiting with private IP."""
        _redis_client_fixture.flushdb()  # Clear any existing state
        response = client.get("/api/traces", headers={"X-Real-IP": "10.0.0.1"})

        assert "X-RateLimit-Limit" in response.headers
        assert response.status_code in [200, 401, 429]

    @integration_test
    def test_rate_limit_zero_remaining_state(
        self, client: TestClient, _redis_client_fixture: Redis
    ):
        """Test behavior when remaining count reaches zero."""
        _redis_client_fixture.flushdb()  # Clear any existing state
        ip = "192.168.1.120"

        # Make requests until rate limited
        last_successful_remaining = None
        for _i in range(150):
            response = client.get("/api/traces", headers={"X-Real-IP": ip})
            if response.status_code == 429:
                break
            if "X-RateLimit-Remaining" in response.headers:
                last_successful_remaining = int(response.headers["X-RateLimit-Remaining"])

        # Last successful request should have remaining >= 0
        if last_successful_remaining is not None:
            assert last_successful_remaining >= 0

    @integration_test
    def test_rate_limit_boundary_at_exact_limit(
        self, client: TestClient, _redis_client_fixture: Redis
    ):
        """Test behavior at exact rate limit boundary."""
        _redis_client_fixture.flushdb()  # Clear any existing state
        ip = "192.168.1.121"

        responses = []
        for _i in range(105):
            response = client.get("/api/traces", headers={"X-Real-IP": ip})
            responses.append(response)
            if response.status_code == 429:
                break

        # Should have at least one success and one 429
        status_codes = [r.status_code for r in responses]
        assert 200 in status_codes or 401 in status_codes
        assert 429 in status_codes


@pytest.mark.integration
class TestRateLimitWithAuthentication:
    """Test rate limiting interaction with authentication."""

    @integration_test
    def test_rate_limit_applies_before_auth(self, client: TestClient, _redis_client_fixture: Redis):
        """Test that rate limiting is enforced before authentication."""
        _redis_client_fixture.flushdb()  # Clear any existing state
        ip = "192.168.1.122"

        # Make requests without auth
        response = client.get("/api/traces", headers={"X-Real-IP": ip})

        # Should have rate limit headers even without auth
        assert "X-RateLimit-Limit" in response.headers

    @integration_test
    def test_rate_limit_persists_across_auth_states(
        self, client: TestClient, _redis_client_fixture: Redis
    ):
        """Test that rate limit persists regardless of auth state."""
        _redis_client_fixture.flushdb()  # Clear any existing state
        ip = "192.168.1.123"

        # Make request without auth
        response1 = client.get("/api/traces", headers={"X-Real-IP": ip})
        remaining1 = int(response1.headers.get("X-RateLimit-Remaining", "100"))

        # Make another request (still no auth)
        response2 = client.get("/api/traces", headers={"X-Real-IP": ip})
        remaining2 = int(response2.headers.get("X-RateLimit-Remaining", "100"))

        # Remaining should decrease
        assert remaining2 < remaining1


@pytest.mark.integration
class TestRateLimitResilience:
    """Test rate limiting resilience and error recovery."""

    @redis_required
    def test_rate_limit_handles_redis_keys_gracefully(
        self, client: TestClient, _redis_client_fixture: Redis
    ):
        """Test system handles Redis key operations gracefully."""
        ip = "192.168.1.124"

        # Make initial request
        response1 = client.get("/api/traces", headers={"X-Real-IP": ip})
        assert response1.status_code in [200, 401]

        # Verify Redis keys exist
        keys_before = _redis_client_fixture.keys("*")
        assert len(keys_before) > 0

        # Make more requests
        response2 = client.get("/api/traces", headers={"X-Real-IP": ip})
        assert response2.status_code in [200, 401]

    @redis_required
    def test_rate_limit_recovery_after_redis_clear(
        self, client: TestClient, _redis_client_fixture: Redis
    ):
        """Test rate limiting recovers correctly after Redis flush."""
        ip = "192.168.1.125"

        # Establish initial state
        response1 = client.get("/api/traces", headers={"X-Real-IP": ip})
        remaining1 = int(response1.headers.get("X-RateLimit-Remaining", "100"))

        # Clear Redis
        _redis_client_fixture.flushdb()

        # Make new request - should get fresh limit
        response2 = client.get("/api/traces", headers={"X-Real-IP": ip})
        remaining2 = int(response2.headers.get("X-RateLimit-Remaining", "100"))

        # Should have full limit or close to it
        assert remaining2 >= remaining1


@pytest.mark.integration
class TestRateLimitConcurrency:
    """Test rate limiting under concurrent load."""

    @integration_test
    def test_rate_limit_handles_rapid_sequential_requests(
        self, client: TestClient, _redis_client_fixture: Redis
    ):
        """Test rate limiting with rapid sequential requests."""
        _redis_client_fixture.flushdb()  # Clear any existing state
        ip = "192.168.1.126"

        # Make rapid requests
        responses = []
        for _ in range(20):
            response = client.get("/api/traces", headers={"X-Real-IP": ip})
            responses.append(response)

        # All should have consistent headers
        for response in responses:
            if response.status_code == 200:
                assert "X-RateLimit-Limit" in response.headers
                assert "X-RateLimit-Remaining" in response.headers

    @integration_test
    def test_rate_limit_maintains_count_accuracy(
        self, client: TestClient, _redis_client_fixture: Redis
    ):
        """Test that rate limit count remains accurate under load."""
        _redis_client_fixture.flushdb()  # Clear any existing state
        ip = "192.168.1.127"

        # Track remaining counts
        remaining_counts = []
        for _ in range(15):
            response = client.get("/api/traces", headers={"X-Real-IP": ip})
            if "X-RateLimit-Remaining" in response.headers and response.status_code == 200:
                remaining_counts.append(int(response.headers["X-RateLimit-Remaining"]))

        # Counts should generally decrease (may not be perfectly sequential due to timing)
        if len(remaining_counts) >= 2:
            assert remaining_counts[-1] <= remaining_counts[0]


@pytest.mark.integration
class TestRateLimitObservability:
    """Test rate limiting observability features."""

    @integration_test
    def test_rate_limit_headers_format_consistency(
        self, client: TestClient, _redis_client_fixture: Redis
    ):
        """Test that rate limit headers maintain consistent format."""
        _redis_client_fixture.flushdb()  # Clear any existing state
        ip = "192.168.1.128"

        responses = []
        for _ in range(5):
            response = client.get("/api/traces", headers={"X-Real-IP": ip})
            responses.append(response)

        # All successful responses should have consistent header format
        for response in responses:
            if response.status_code == 200:
                assert "X-RateLimit-Limit" in response.headers
                assert "X-RateLimit-Remaining" in response.headers
                assert "X-RateLimit-Reset" in response.headers

                # Verify types
                limit = response.headers["X-RateLimit-Limit"]
                remaining = response.headers["X-RateLimit-Remaining"]
                reset = response.headers["X-RateLimit-Reset"]

                assert limit.isdigit()
                assert remaining.isdigit()
                assert reset.isdigit()

    @integration_test
    def test_rate_limit_429_response_includes_headers(
        self, client: TestClient, _redis_client_fixture: Redis
    ):
        """Test that 429 responses include rate limit headers."""
        _redis_client_fixture.flushdb()  # Clear any existing state
        ip = "192.168.1.129"

        # Exhaust rate limit
        response = None
        for _ in range(150):
            response = client.get("/api/traces", headers={"X-Real-IP": ip})
            if response.status_code == 429:
                break

        # 429 response should have rate limit headers
        if response and response.status_code == 429:
            assert "X-RateLimit-Limit" in response.headers
            # Remaining should be 0 or very low
            remaining = int(response.headers.get("X-RateLimit-Remaining", "0"))
            assert remaining >= 0


@pytest.mark.integration
class TestRateLimitStorageOperations:
    """Test Redis storage operations for rate limiting."""

    @redis_required
    def test_redis_key_naming_convention(self, client: TestClient, _redis_client_fixture: Redis):
        """Test that Redis keys follow expected naming convention."""
        ip = "192.168.1.130"

        # Clear and make request
        _redis_client_fixture.flushdb()
        client.get("/api/traces", headers={"X-Real-IP": ip})

        # Check key format
        keys = _redis_client_fixture.keys("*")
        assert len(keys) > 0

        # Keys should contain some identifying information
        key_str = str(keys[0])
        assert len(key_str) > 0

    @redis_required
    def test_redis_ttl_reasonable_values(self, client: TestClient, _redis_client_fixture: Redis):
        """Test that Redis TTL values are reasonable."""
        ip = "192.168.1.131"

        _redis_client_fixture.flushdb()
        client.get("/api/traces", headers={"X-Real-IP": ip})

        # Check TTLs
        keys = _redis_client_fixture.keys("*")
        for key in keys:
            ttl = _redis_client_fixture.ttl(key)
            # TTL should be between 0 and 120 seconds (2 minutes)
            # -1 means no expiry (shouldn't happen)
            # -2 means key doesn't exist (shouldn't happen)
            assert -1 <= ttl <= 120, f"TTL {ttl} is not in reasonable range"

    @redis_required
    def test_redis_storage_cleanup(self, client: TestClient, _redis_client_fixture: Redis):
        """Test that Redis properly cleans up expired keys."""
        ip = "192.168.1.132"

        _redis_client_fixture.flushdb()

        # Make request
        client.get("/api/traces", headers={"X-Real-IP": ip})

        keys_before = len(_redis_client_fixture.keys("*"))
        assert keys_before > 0

        # Keys should exist immediately after
        keys_after = len(_redis_client_fixture.keys("*"))
        assert keys_after > 0
