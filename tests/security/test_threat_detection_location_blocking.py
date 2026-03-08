"""Threat detection tests: new location and IP blocking.

This test suite covers:
- New location detection tests (5 tests)
- IP blocking tests (5 tests)

Sibling modules:
- test_threat_detection.py (brute force, escalation, exfiltration)
- test_threat_detection_advanced.py (patterns, integration, alerts)

Enterprise Engineering Protocols 2025
Zero trust security model
"""

from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import MagicMock

import pytest

from server.policy_governance.kernel.threat_detector import (
    ThreatDetector,
    ThreatSeverity,
    ThreatType,
)

# =============================================================================
# Test Fixtures
# =============================================================================


@dataclass
class MockUser:
    """Mock user object implementing UserProtocol."""

    id: int
    email: str
    role: str


@pytest.fixture(name="mock_user")
def _mock_user_impl() -> MockUser:
    """Create a standard mock user for testing."""
    return MockUser(id=1, email="user@example.com", role="user")


@pytest.fixture(name="mock_redis")
def _mock_redis_impl() -> MagicMock:
    """Create a mock Redis client."""
    redis = MagicMock()
    redis.incr = MagicMock(return_value=1)
    redis.expire = MagicMock(return_value=True)
    redis.get = MagicMock(return_value="1")
    redis.delete = MagicMock(return_value=1)
    redis.setex = MagicMock(return_value=True)
    redis.sadd = MagicMock(return_value=1)
    redis.srem = MagicMock(return_value=1)
    redis.smembers = MagicMock(return_value=set())
    redis.sismember = MagicMock(return_value=False)
    redis.exists = MagicMock(return_value=False)
    redis.ping = MagicMock(return_value=True)
    redis.pipeline = MagicMock(return_value=MagicMock())

    pipe_mock = MagicMock()
    pipe_mock.zremrangebyscore = MagicMock()
    pipe_mock.zadd = MagicMock()
    pipe_mock.zcard = MagicMock()
    pipe_mock.expire = MagicMock()
    pipe_mock.execute = MagicMock(return_value=[None, None, 1, True])
    redis.pipeline.return_value = pipe_mock

    return redis


@pytest.fixture(name="threat_detector")
def _threat_detector_impl(
    mock_redis: MagicMock,
) -> ThreatDetector:
    """Create a ThreatDetector with mocked dependencies."""
    return ThreatDetector(
        redis_client=mock_redis,
        enable_metrics=False,
        auto_block=True,
    )


@pytest.fixture(name="threat_detector_no_redis")
def _threat_detector_no_redis_impl() -> ThreatDetector:
    """Create a ThreatDetector without Redis (in-memory)."""
    return ThreatDetector(
        redis_client=None,
        enable_metrics=False,
        auto_block=True,
    )


# =============================================================================
# New Location Detection Tests (5 tests)
# =============================================================================


class TestNewLocationDetection:
    """Tests for new location/IP detection."""

    def test_new_location_first_login_no_alert(
        self,
        threat_detector_no_redis: ThreatDetector,
        mock_user: MockUser,
    ) -> None:
        """First login should not trigger alert."""
        result = threat_detector_no_redis.check_new_location(
            user=mock_user,
            ip="192.168.1.1",
            user_agent="Mozilla/5.0",
        )

        assert result is None

    def test_new_location_same_ip_no_alert(
        self,
        threat_detector_no_redis: ThreatDetector,
        mock_user: MockUser,
    ) -> None:
        """Login from same IP should not trigger alert."""
        threat_detector_no_redis.check_new_location(
            user=mock_user,
            ip="192.168.1.1",
            user_agent="Mozilla/5.0",
        )

        result = threat_detector_no_redis.check_new_location(
            user=mock_user,
            ip="192.168.1.1",
            user_agent="Mozilla/5.0",
        )

        assert result is None

    def test_new_location_different_ip_triggers_alert(
        self,
        threat_detector_no_redis: ThreatDetector,
        mock_user: MockUser,
    ) -> None:
        """Login from new IP should trigger alert."""
        threat_detector_no_redis.check_new_location(
            user=mock_user,
            ip="192.168.1.1",
            user_agent="Mozilla/5.0",
        )

        result = threat_detector_no_redis.check_new_location(
            user=mock_user,
            ip="10.0.0.100",
            user_agent="Mozilla/5.0",
        )

        assert result is not None
        assert result.event_type == ThreatType.NEW_LOCATION
        assert result.severity == ThreatSeverity.MEDIUM
        assert result.details["new_ip"] == "10.0.0.100"

    def test_new_location_captures_user_agent(
        self,
        threat_detector_no_redis: ThreatDetector,
        mock_user: MockUser,
    ) -> None:
        """User agent should be captured in event."""
        threat_detector_no_redis.check_new_location(
            user=mock_user,
            ip="192.168.1.1",
            user_agent="Mozilla/5.0",
        )

        new_user_agent = "curl/7.64.1"
        result = threat_detector_no_redis.check_new_location(
            user=mock_user,
            ip="10.0.0.200",
            user_agent=new_user_agent,
        )

        assert result is not None
        assert result.user_agent == new_user_agent
        assert result.details["user_agent"] == new_user_agent

    def test_new_location_tracks_known_ips_count(
        self,
        threat_detector_no_redis: ThreatDetector,
        mock_user: MockUser,
    ) -> None:
        """Known IPs count should be tracked."""
        threat_detector_no_redis.check_new_location(
            user=mock_user,
            ip="192.168.1.1",
            user_agent="Mozilla/5.0",
        )
        threat_detector_no_redis.check_new_location(
            user=mock_user,
            ip="192.168.1.2",
            user_agent="Mozilla/5.0",
        )

        result = threat_detector_no_redis.check_new_location(
            user=mock_user,
            ip="10.0.0.100",
            user_agent="Mozilla/5.0",
        )

        assert result is not None
        assert result.details["known_ips_count"] >= 2


# =============================================================================
# IP Blocking Tests (5 tests)
# =============================================================================


class TestIPBlocking:
    """Tests for IP blocking functionality."""

    def test_ip_blocking_manual_block(
        self,
        threat_detector: ThreatDetector,
    ) -> None:
        """Manually blocked IP should be detected."""
        test_ip = "192.168.100.1"

        threat_detector.block_ip(test_ip, "manual_test", duration=3600)

        assert threat_detector.is_blocked(test_ip)

    def test_ip_blocking_unblock(
        self,
        threat_detector: ThreatDetector,
    ) -> None:
        """Unblocking should remove IP from list."""
        test_ip = "192.168.100.2"

        threat_detector.block_ip(test_ip, "test")
        assert threat_detector.is_blocked(test_ip)

        was_blocked = threat_detector.unblock_ip(test_ip)
        assert was_blocked is True
        assert not threat_detector.is_blocked(test_ip)

    def test_ip_blocking_unblock_not_blocked(
        self,
        threat_detector: ThreatDetector,
    ) -> None:
        """Unblocking non-blocked IP returns False."""
        result = threat_detector.unblock_ip("10.0.0.99")
        assert result is False

    def test_ip_blocking_get_all_blocked(
        self,
        threat_detector_no_redis: ThreatDetector,
    ) -> None:
        """Should return all blocked IPs."""
        ips = [
            "192.168.1.1",
            "192.168.1.2",
            "192.168.1.3",
        ]

        for ip in ips:
            threat_detector_no_redis.block_ip(ip, "test")

        blocked = threat_detector_no_redis.get_blocked_ips()
        for ip in ips:
            assert ip in blocked

    def test_ip_blocking_increments_stats(
        self,
        threat_detector: ThreatDetector,
    ) -> None:
        """Blocking should increment stats."""
        initial_blocked = threat_detector.stats["ips_blocked"]

        threat_detector.block_ip("192.168.200.1", "test")

        assert threat_detector.stats["ips_blocked"] == initial_blocked + 1
