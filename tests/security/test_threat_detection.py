"""Threat detection tests: brute force, escalation, and exfiltration.

This test suite validates the core threat detection engine with:
- Brute force detection tests (10 tests)
- Privilege escalation detection tests (10 tests)
- Data exfiltration detection tests (10 tests)

Additional tests split into sibling modules:
- test_threat_detection_location_blocking.py (new location, IP blocking)
- test_threat_detection_advanced.py (patterns, integration, alerts)

References:
- OWASP Top 10 Web Application Security Risks
- Enterprise Engineering Protocols 2025
"""

from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import MagicMock

import pytest

from server.policy_governance.kernel.threat_detector import (
    ThreatDetector,
    ThreatEvent,
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


@pytest.fixture(name="mock_admin_user")
def _mock_admin_user_impl() -> MockUser:
    """Create a mock admin user for testing."""
    return MockUser(id=2, email="admin@example.com", role="admin")


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

    # Pipeline mock
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
# Brute Force Detection Tests (10 tests)
# =============================================================================


class TestBruteForceDetection:
    """Tests for brute force login attempt detection."""

    def test_brute_force_no_threat_on_single_failure(
        self,
        threat_detector: ThreatDetector,
    ) -> None:
        """Single failed login should not trigger detection."""
        result = threat_detector.check_brute_force(
            ip="192.168.1.100",
            email="user@example.com",
            success=False,
        )
        assert result is None

    def test_brute_force_resets_on_success(
        self,
        threat_detector: ThreatDetector,
    ) -> None:
        """Successful login should reset the failure counter."""
        for _ in range(5):
            threat_detector.check_brute_force(
                ip="192.168.1.101",
                email="user@example.com",
                success=False,
            )

        result = threat_detector.check_brute_force(
            ip="192.168.1.101",
            email="user@example.com",
            success=True,
        )
        assert result is None

    def test_brute_force_high_severity_threshold(
        self,
        threat_detector_no_redis: ThreatDetector,
    ) -> None:
        """10+ failures should trigger HIGH severity."""
        ip = "192.168.1.102"
        result = None

        for _ in range(11):
            result = threat_detector_no_redis.check_brute_force(
                ip=ip,
                email="victim@example.com",
                success=False,
            )

        assert result is not None
        assert result.severity == ThreatSeverity.HIGH
        assert result.event_type == ThreatType.BRUTE_FORCE
        assert result.details["failed_attempts"] >= 10

    def test_brute_force_critical_severity_auto_block(
        self,
        threat_detector_no_redis: ThreatDetector,
    ) -> None:
        """20+ failures trigger CRITICAL and auto-block."""
        ip = "192.168.1.103"
        result = None

        for _ in range(21):
            result = threat_detector_no_redis.check_brute_force(
                ip=ip,
                email="victim@example.com",
                success=False,
            )

        assert result is not None
        assert result.severity == ThreatSeverity.CRITICAL
        assert result.blocked is True
        assert result.action_taken == "ip_blocked"
        assert threat_detector_no_redis.is_blocked(ip)

    def test_brute_force_with_user_agent(
        self,
        threat_detector_no_redis: ThreatDetector,
    ) -> None:
        """User agent should be captured in threat event."""
        ip = "192.168.1.104"
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

        for _ in range(11):
            result = threat_detector_no_redis.check_brute_force(
                ip=ip,
                email="test@example.com",
                success=False,
                user_agent=user_agent,
            )

        assert result is not None
        assert result.user_agent == user_agent

    def test_brute_force_different_ips_independent(
        self,
        threat_detector_no_redis: ThreatDetector,
    ) -> None:
        """Different IPs track failures independently."""
        for _ in range(5):
            threat_detector_no_redis.check_brute_force(
                ip="10.0.0.1",
                email="user@example.com",
                success=False,
            )

        for _ in range(5):
            threat_detector_no_redis.check_brute_force(
                ip="10.0.0.2",
                email="user@example.com",
                success=False,
            )

        assert not threat_detector_no_redis.is_blocked("10.0.0.1")
        assert not threat_detector_no_redis.is_blocked("10.0.0.2")

    def test_brute_force_same_ip_different_emails(
        self,
        threat_detector_no_redis: ThreatDetector,
    ) -> None:
        """Multiple emails from same IP aggregate."""
        ip = "192.168.1.105"
        result = None

        for _ in range(6):
            threat_detector_no_redis.check_brute_force(
                ip=ip,
                email="user1@example.com",
                success=False,
            )

        for _ in range(5):
            result = threat_detector_no_redis.check_brute_force(
                ip=ip,
                email="user2@example.com",
                success=False,
            )

        assert result is not None
        assert result.severity == ThreatSeverity.HIGH

    def test_brute_force_event_contains_target_email(
        self,
        threat_detector_no_redis: ThreatDetector,
    ) -> None:
        """Threat event should contain the target email."""
        ip = "192.168.1.106"
        target_email = "targeted@example.com"

        for _ in range(11):
            result = threat_detector_no_redis.check_brute_force(
                ip=ip,
                email=target_email,
                success=False,
            )

        assert result is not None
        assert result.details["target_email"] == target_email

    def test_brute_force_stats_increment(
        self,
        threat_detector: ThreatDetector,
    ) -> None:
        """Stats should be incremented on detection."""
        initial_checks = threat_detector.stats["total_checks"]

        threat_detector.check_brute_force(
            ip="192.168.1.107",
            email="user@example.com",
            success=False,
        )

        assert threat_detector.stats["total_checks"] == initial_checks + 1

    def test_brute_force_event_id_unique(
        self,
        threat_detector_no_redis: ThreatDetector,
    ) -> None:
        """Each threat event should have a unique ID."""
        ip = "192.168.1.108"
        events: list[ThreatEvent] = []

        for _ in range(12):
            result = threat_detector_no_redis.check_brute_force(
                ip=ip,
                email="test@example.com",
                success=False,
            )
            if result:
                events.append(result)

        assert len(events) >= 1
        event_ids = [e.event_id for e in events]
        assert len(event_ids) == len(set(event_ids))


# =============================================================================
# Privilege Escalation Detection Tests (10 tests)
# =============================================================================


class TestPrivilegeEscalationDetection:
    """Tests for privilege escalation attempt detection."""

    def test_privilege_escalation_admin_action_by_user(
        self,
        threat_detector: ThreatDetector,
        mock_user: MockUser,
    ) -> None:
        """Non-admin admin action should trigger alert."""
        result = threat_detector.check_privilege_escalation(
            user=mock_user,
            action="admin_delete_user",
            ip="192.168.1.1",
        )

        assert result is not None
        assert result.event_type == ThreatType.PRIVILEGE_ESCALATION
        assert result.severity == ThreatSeverity.CRITICAL
        assert result.user_id == mock_user.id
        assert result.user_email == mock_user.email

    def test_privilege_escalation_admin_action_by_admin(
        self,
        threat_detector: ThreatDetector,
        mock_admin_user: MockUser,
    ) -> None:
        """Admin performing admin action is allowed."""
        result = threat_detector.check_privilege_escalation(
            user=mock_admin_user,
            action="admin_delete_user",
            ip="192.168.1.1",
        )

        assert result is None

    def test_privilege_escalation_role_attempt(
        self,
        threat_detector: ThreatDetector,
        mock_user: MockUser,
    ) -> None:
        """User escalating to admin triggers alert."""
        result = threat_detector.check_privilege_escalation(
            user=mock_user,
            action="update_role",
            target_role="admin",
            ip="192.168.1.1",
        )

        assert result is not None
        assert result.event_type == ThreatType.ROLE_ESCALATION
        assert result.severity == ThreatSeverity.CRITICAL
        assert result.details["current_role"] == "user"
        assert result.details["target_role"] == "admin"

    def test_privilege_escalation_admin_can_grant(
        self,
        threat_detector: ThreatDetector,
        mock_admin_user: MockUser,
    ) -> None:
        """Admin granting admin role is allowed."""
        result = threat_detector.check_privilege_escalation(
            user=mock_admin_user,
            action="update_role",
            target_role="admin",
            ip="192.168.1.1",
        )

        assert result is None

    def test_privilege_escalation_non_admin_allowed(
        self,
        threat_detector: ThreatDetector,
        mock_user: MockUser,
    ) -> None:
        """Regular user actions should not trigger."""
        result = threat_detector.check_privilege_escalation(
            user=mock_user,
            action="read_profile",
            ip="192.168.1.1",
        )

        assert result is None

    def test_privilege_escalation_captures_ip(
        self,
        threat_detector: ThreatDetector,
        mock_user: MockUser,
    ) -> None:
        """IP address should be captured in event."""
        test_ip = "10.0.0.50"
        result = threat_detector.check_privilege_escalation(
            user=mock_user,
            action="admin_modify_settings",
            ip=test_ip,
        )

        assert result is not None
        assert result.ip_address == test_ip

    def test_privilege_escalation_unknown_ip(
        self,
        threat_detector: ThreatDetector,
        mock_user: MockUser,
    ) -> None:
        """Missing IP should default to 'unknown'."""
        result = threat_detector.check_privilege_escalation(
            user=mock_user,
            action="admin_export_data",
        )

        assert result is not None
        assert result.ip_address == "unknown"

    def test_privilege_escalation_increments_stats(
        self,
        threat_detector: ThreatDetector,
        mock_user: MockUser,
    ) -> None:
        """Stats should be incremented on detection."""
        initial_threats = threat_detector.stats["threats_detected"]

        threat_detector.check_privilege_escalation(
            user=mock_user,
            action="admin_action",
            ip="192.168.1.1",
        )

        assert threat_detector.stats["threats_detected"] == initial_threats + 1

    def test_privilege_escalation_role_downgrade(
        self,
        threat_detector: ThreatDetector,
        mock_user: MockUser,
    ) -> None:
        """Downgrading to lower role is allowed."""
        result = threat_detector.check_privilege_escalation(
            user=mock_user,
            action="update_role",
            target_role="readonly",
            ip="192.168.1.1",
        )

        assert result is None

    def test_privilege_escalation_description(
        self,
        threat_detector: ThreatDetector,
        mock_user: MockUser,
    ) -> None:
        """Threat event contains descriptive details."""
        result = threat_detector.check_privilege_escalation(
            user=mock_user,
            action="admin_system_config",
            ip="192.168.1.1",
        )

        assert result is not None
        assert "description" in result.details
        assert mock_user.email in result.details["description"]


# =============================================================================
# Data Exfiltration Detection Tests (10 tests)
# =============================================================================


class TestDataExfiltrationDetection:
    """Tests for data exfiltration attempt detection."""

    def test_data_exfiltration_high_request_rate(
        self,
        threat_detector_no_redis: ThreatDetector,
        mock_user: MockUser,
    ) -> None:
        """High request rate should trigger alert."""
        result = None
        detector = threat_detector_no_redis
        for _ in range(101):
            result = detector.check_data_exfiltration(
                user=mock_user,
                endpoint="/api/users",
                response_size=1024,
                ip="192.168.1.1",
            )

        assert result is not None
        assert result.event_type == ThreatType.DATA_EXFILTRATION
        assert result.severity == ThreatSeverity.HIGH
        assert result.details["request_rate"] > 100

    def test_data_exfiltration_large_response(
        self,
        threat_detector: ThreatDetector,
        mock_user: MockUser,
    ) -> None:
        """Large response size should trigger alert."""
        large_response_size = 11 * 1024 * 1024

        result = threat_detector.check_data_exfiltration(
            user=mock_user,
            endpoint="/api/export",
            response_size=large_response_size,
            ip="192.168.1.1",
        )

        assert result is not None
        assert result.event_type == ThreatType.DATA_EXFILTRATION
        assert result.severity == ThreatSeverity.MEDIUM
        assert result.details["response_size_mb"] > 10

    def test_data_exfiltration_normal_allowed(
        self,
        threat_detector: ThreatDetector,
        mock_user: MockUser,
    ) -> None:
        """Normal request rate and size is allowed."""
        result = threat_detector.check_data_exfiltration(
            user=mock_user,
            endpoint="/api/users",
            response_size=10240,
            ip="192.168.1.1",
        )

        assert result is None

    def test_data_exfiltration_captures_endpoint(
        self,
        threat_detector: ThreatDetector,
        mock_user: MockUser,
    ) -> None:
        """Endpoint should be captured in event."""
        test_endpoint = "/api/sensitive/data"
        large_response = 15 * 1024 * 1024

        result = threat_detector.check_data_exfiltration(
            user=mock_user,
            endpoint=test_endpoint,
            response_size=large_response,
            ip="192.168.1.1",
        )

        assert result is not None
        assert result.endpoint == test_endpoint
        assert result.details["endpoint"] == test_endpoint

    def test_data_exfiltration_per_user_endpoint(
        self,
        threat_detector_no_redis: ThreatDetector,
    ) -> None:
        """Rate tracking is per user+endpoint pair."""
        detector = threat_detector_no_redis
        user1 = MockUser(id=1, email="user1@example.com", role="user")
        user2 = MockUser(id=2, email="user2@example.com", role="user")

        for _ in range(50):
            detector.check_data_exfiltration(
                user=user1,
                endpoint="/api/data",
                response_size=1024,
                ip="192.168.1.1",
            )

        result = None
        for _ in range(50):
            result = detector.check_data_exfiltration(
                user=user2,
                endpoint="/api/data",
                response_size=1024,
                ip="192.168.1.2",
            )
        assert result is None

    def test_data_exfiltration_endpoints_independent(
        self,
        threat_detector_no_redis: ThreatDetector,
        mock_user: MockUser,
    ) -> None:
        """Different endpoints track independently."""
        detector = threat_detector_no_redis
        for _ in range(50):
            detector.check_data_exfiltration(
                user=mock_user,
                endpoint="/api/endpoint1",
                response_size=1024,
                ip="192.168.1.1",
            )

        result = None
        for _ in range(50):
            result = detector.check_data_exfiltration(
                user=mock_user,
                endpoint="/api/endpoint2",
                response_size=1024,
                ip="192.168.1.1",
            )
        assert result is None

    def test_data_exfiltration_includes_user_info(
        self,
        threat_detector: ThreatDetector,
        mock_user: MockUser,
    ) -> None:
        """Threat event should include user info."""
        large_response = 15 * 1024 * 1024

        result = threat_detector.check_data_exfiltration(
            user=mock_user,
            endpoint="/api/export",
            response_size=large_response,
            ip="192.168.1.1",
        )

        assert result is not None
        assert result.user_id == mock_user.id
        assert result.user_email == mock_user.email

    def test_data_exfiltration_size_calculation(
        self,
        threat_detector: ThreatDetector,
        mock_user: MockUser,
    ) -> None:
        """Response size in MB is calculated correctly."""
        result = threat_detector.check_data_exfiltration(
            user=mock_user,
            endpoint="/api/export",
            response_size=10 * 1024 * 1024,
            ip="192.168.1.1",
        )
        assert result is None

        result = threat_detector.check_data_exfiltration(
            user=mock_user,
            endpoint="/api/export",
            response_size=10 * 1024 * 1024 + 1,
            ip="192.168.1.1",
        )
        assert result is not None

    def test_data_exfiltration_increments_stats(
        self,
        threat_detector: ThreatDetector,
        mock_user: MockUser,
    ) -> None:
        """Stats should be incremented on detection."""
        initial_checks = threat_detector.stats["total_checks"]
        initial_threats = threat_detector.stats["threats_detected"]

        threat_detector.check_data_exfiltration(
            user=mock_user,
            endpoint="/api/export",
            response_size=15 * 1024 * 1024,
            ip="192.168.1.1",
        )

        assert threat_detector.stats["total_checks"] == initial_checks + 1
        assert threat_detector.stats["threats_detected"] == initial_threats + 1

    def test_data_exfiltration_missing_ip_defaults(
        self,
        threat_detector: ThreatDetector,
        mock_user: MockUser,
    ) -> None:
        """Missing IP should default to 'unknown'."""
        result = threat_detector.check_data_exfiltration(
            user=mock_user,
            endpoint="/api/export",
            response_size=15 * 1024 * 1024,
        )

        assert result is not None
        assert result.ip_address == "unknown"
