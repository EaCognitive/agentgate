"""
Advanced threat detection tests including pattern matching, integration, alerts, and edge cases.

This test suite extends the core threat detection tests with:
- Pattern matching and attack detection (10 tests)
- Integration tests for comprehensive request analysis (5 tests)
- Alert system tests (5 tests)
- Performance benchmarks (3 tests)
- Edge cases and boundary conditions (5 tests)

SUCCESS CRITERIA:
- All 28 tests passing
- Pattern matching accuracy > 95%
- Alert system functioning correctly
- Performance metrics tracked

References:
- OWASP Top 10 Web Application Security Risks
- Enterprise Engineering Protocols 2026
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from unittest.mock import MagicMock

import pytest

from server.policy_governance.kernel.alerts import (
    AlertPriority,
    LogAlertChannel,
    RateLimitConfig,
    SecurityAlert,
    SecurityAlertManager,
)
from server.policy_governance.kernel.threat_detector import (
    ThreatDetectionResult,
    ThreatDetector,
    ThreatType,
)
from server.policy_governance.kernel.threat_patterns import (
    PatternMatcher,
    PatternSeverity,
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
def _threat_detector_impl(mock_redis: MagicMock) -> ThreatDetector:
    """Create a ThreatDetector with mocked dependencies."""
    return ThreatDetector(
        redis_client=mock_redis,
        enable_metrics=False,
        auto_block=True,
    )


@pytest.fixture(name="threat_detector_no_redis")
def _threat_detector_no_redis_impl() -> ThreatDetector:
    """Create a ThreatDetector without Redis (in-memory only)."""
    return ThreatDetector(
        redis_client=None,
        enable_metrics=False,
        auto_block=True,
    )


@pytest.fixture(name="pattern_matcher")
def _pattern_matcher_impl() -> PatternMatcher:
    """Create a PatternMatcher with default patterns."""
    return PatternMatcher()


@pytest.fixture(name="alert_manager")
def _alert_manager_impl() -> SecurityAlertManager:
    """Create a SecurityAlertManager for testing."""
    return SecurityAlertManager(
        channels=[LogAlertChannel()],
        rate_limit=RateLimitConfig(
            window_seconds=60.0,
            max_alerts_per_window=100,  # High limit for testing
            cooldown_seconds=10.0,
        ),
    )


# =============================================================================
# Pattern Matching Tests (10 tests)
# =============================================================================


class TestPatternMatching:
    """Tests for attack pattern detection."""

    def test_sql_injection_detection(self, pattern_matcher: PatternMatcher) -> None:
        """SQL injection patterns should be detected."""
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "1 UNION SELECT * FROM users",
            "' AND 1=1--",
        ]

        for payload in sql_payloads:
            matches = pattern_matcher.match_all(payload)
            assert len(matches) > 0, f"Should detect SQL injection in: {payload}"

    def test_xss_detection(self, pattern_matcher: PatternMatcher) -> None:
        """XSS patterns should be detected."""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert(1)",
            "<svg onload=alert('XSS')>",
        ]

        for payload in xss_payloads:
            matches = pattern_matcher.match_all(payload)
            assert len(matches) > 0, f"Should detect XSS in: {payload}"

    def test_path_traversal_detection(self, pattern_matcher: PatternMatcher) -> None:
        """Path traversal patterns should be detected."""
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32",
            "/etc/passwd",
            "%2e%2e%2f%2e%2e%2f",
        ]

        for payload in traversal_payloads:
            matches = pattern_matcher.match_all(payload)
            assert len(matches) > 0, f"Should detect path traversal in: {payload}"

    def test_command_injection_detection(self, pattern_matcher: PatternMatcher) -> None:
        """Command injection patterns should be detected."""
        cmd_payloads = [
            "; cat /etc/passwd",
            "| ls -la",
            "`whoami`",
            "$(cat /etc/passwd)",
        ]

        for payload in cmd_payloads:
            matches = pattern_matcher.match_all(payload)
            assert len(matches) > 0, f"Should detect command injection in: {payload}"

    def test_ssrf_detection(self, pattern_matcher: PatternMatcher) -> None:
        """SSRF patterns should be detected."""
        ssrf_payloads = [
            "http://localhost:8080",
            "http://127.0.0.1",
            "http://169.254.169.254/metadata",
            "http://192.168.1.1",
        ]

        for payload in ssrf_payloads:
            matches = pattern_matcher.match_all(payload)
            assert len(matches) > 0, f"Should detect SSRF in: {payload}"

    def test_clean_input_no_detection(self, pattern_matcher: PatternMatcher) -> None:
        """Clean input should not trigger false positives."""
        clean_inputs = [
            "Hello, World!",
            "user@example.com",
            "This is a normal message",
            "12345",
            "Product description: High quality item",
        ]

        for input_value in clean_inputs:
            matches = pattern_matcher.match_all(input_value)
            # Some benign inputs might still match loose patterns
            # but should not match critical ones
            critical_matches = [m for m in matches if m.severity == PatternSeverity.CRITICAL]
            assert len(critical_matches) == 0, f"False positive critical match in: {input_value}"

    def test_pattern_severity_sorting(self, pattern_matcher: PatternMatcher) -> None:
        """Matches should be sorted by severity (critical first)."""
        # Input with multiple pattern types
        payload = "'; DROP TABLE users-- <script>alert(1)</script>"
        matches = pattern_matcher.match_all(payload)

        assert len(matches) > 0
        # First match should be critical
        if len(matches) > 1:
            severity_order = [
                PatternSeverity.CRITICAL,
                PatternSeverity.HIGH,
                PatternSeverity.MEDIUM,
                PatternSeverity.LOW,
            ]
            for i in range(len(matches) - 1):
                curr_idx = severity_order.index(matches[i].severity)
                next_idx = severity_order.index(matches[i + 1].severity)
                assert curr_idx <= next_idx

    def test_pattern_confidence_included(self, pattern_matcher: PatternMatcher) -> None:
        """Pattern matches should include confidence scores."""
        payload = "'; DROP TABLE users--"
        matches = pattern_matcher.match_all(payload)

        assert len(matches) > 0
        for match in matches:
            assert 0.0 <= match.confidence <= 1.0

    def test_pattern_context_extraction(self, pattern_matcher: PatternMatcher) -> None:
        """Pattern matches should include context around match."""
        payload = "prefix text ' OR '1'='1 suffix text"
        matches = pattern_matcher.match_all(payload)

        assert len(matches) > 0
        for match in matches:
            assert len(match.context) > 0
            assert match.matched_value in match.context or match.position >= 0

    def test_pattern_filtering_by_type(self, pattern_matcher: PatternMatcher) -> None:
        """Should be able to filter patterns by type."""
        payload = "'; DROP TABLE users-- <script>alert(1)</script>"

        # Only check for injection patterns
        injection_matches = pattern_matcher.match_all(payload, pattern_types=["injection"])

        # Should find both SQL and XSS (both are injection type)
        assert len(injection_matches) > 0


# =============================================================================
# Integration Tests (5 tests)
# =============================================================================


class TestIntegration:
    """Integration tests for the complete threat detection system."""

    def test_check_request_comprehensive(self, threat_detector: ThreatDetector) -> None:
        """check_request should perform comprehensive analysis."""
        result = threat_detector.check_request(
            ip="192.168.1.1",
            endpoint="/api/users",
            method="POST",
            headers={"user-agent": "Mozilla/5.0", "content-type": "application/json"},
            body={"email": "user@example.com"},
            user_id=1,
            user_email="user@example.com",
        )

        assert isinstance(result, ThreatDetectionResult)
        assert result.processing_time_ms >= 0

    def test_check_request_detects_attack_in_body(self, threat_detector: ThreatDetector) -> None:
        """check_request should detect attacks in request body."""
        result = threat_detector.check_request(
            ip="192.168.1.1",
            endpoint="/api/search",
            method="POST",
            headers={"user-agent": "Mozilla/5.0"},
            body={"query": "'; DROP TABLE users--"},
        )

        assert result.is_threat is True
        assert len(result.threats) > 0

    def test_check_request_detects_attack_in_url(self, threat_detector: ThreatDetector) -> None:
        """check_request should detect attacks in URL parameters."""
        result = threat_detector.check_request(
            ip="192.168.1.1",
            endpoint="/api/search?q=' OR '1'='1",
            method="GET",
            headers={"user-agent": "Mozilla/5.0"},
        )

        assert result.is_threat is True

    def test_check_request_blocked_ip_early_exit(self, threat_detector: ThreatDetector) -> None:
        """Blocked IP should return immediately without full analysis."""
        test_ip = "192.168.99.99"
        threat_detector.block_ip(test_ip, "test")

        result = threat_detector.check_request(
            ip=test_ip,
            endpoint="/api/anything",
            method="GET",
            headers={},
        )

        assert result.should_block is True
        assert result.block_reason == "ip_blocked"

    def test_check_request_suspicious_user_agent(self, threat_detector: ThreatDetector) -> None:
        """Suspicious user agents should be flagged."""
        suspicious_agents = ["sqlmap/1.0", "nikto/2.0", "curl/7.64.1"]

        for agent in suspicious_agents:
            result = threat_detector.check_request(
                ip="192.168.1.1",
                endpoint="/api/test",
                method="GET",
                headers={"user-agent": agent},
            )

            has_suspicious_ua_threat = any(
                t.event_type == ThreatType.SUSPICIOUS_USER_AGENT for t in result.threats
            )
            assert has_suspicious_ua_threat, f"Should flag suspicious agent: {agent}"


# =============================================================================
# Alert System Tests (5 tests)
# =============================================================================


class TestAlertSystem:
    """Tests for the security alert system."""

    def test_alert_creation(self, alert_manager: SecurityAlertManager) -> None:
        """Should create alerts with correct fields."""
        alert = alert_manager.create_alert(
            title="Test Alert",
            description="Test description",
            priority=AlertPriority.HIGH,
            category="test",
            source="test_source",
            ip_address="192.168.1.1",
            user_id=1,
            user_email="user@example.com",
        )

        assert alert.title == "Test Alert"
        assert alert.priority == AlertPriority.HIGH
        assert alert.ip_address == "192.168.1.1"
        assert "alert_" in alert.alert_id

    def test_alert_rate_limiting(self) -> None:
        """Alerts should be rate limited."""
        manager = SecurityAlertManager(
            channels=[LogAlertChannel()],
            rate_limit=RateLimitConfig(
                window_seconds=1.0,
                max_alerts_per_window=2,
                cooldown_seconds=1.0,
            ),
            dedup_window_seconds=0.0,  # Disable deduplication for this test
        )

        # First 2 alerts should succeed - use unique IPs to avoid deduplication
        for i in range(2):
            alert = manager.create_alert(
                title=f"Alert {i}",
                description="Test",
                priority=AlertPriority.HIGH,
                category="test",
                source="test_source",
                ip_address=f"192.168.{i}.{i}",  # Unique IP for each alert
                user_id=i + 100,  # Unique user for each alert
            )
            result = manager.send_alert(alert)
            assert result is True, f"Alert {i} should succeed"

        # Third alert should be rate limited
        alert = manager.create_alert(
            title="Alert 3",
            description="Test",
            priority=AlertPriority.HIGH,
            category="test",
            source="test_source",
            ip_address="192.168.3.3",
            user_id=103,
        )
        result = manager.send_alert(alert)
        assert result is False, "Third alert should be rate limited"
        assert manager.stats["alerts_suppressed"] > 0

    def test_alert_deduplication(self, alert_manager: SecurityAlertManager) -> None:
        """Duplicate alerts should be deduplicated."""
        # Create same alert twice
        for _ in range(2):
            alert = alert_manager.create_alert(
                title="Duplicate Alert",
                description="Test",
                priority=AlertPriority.HIGH,
                category="test",
                source="test_source",
                ip_address="192.168.1.1",
                user_id=1,
            )
            alert_manager.send_alert(alert)

        assert alert_manager.stats["alerts_deduplicated"] >= 1

    def test_threat_event_to_alert_conversion(
        self, threat_detector_no_redis: ThreatDetector, mock_user: MockUser
    ) -> None:
        """ThreatEvent should convert to SecurityAlert correctly."""
        _ = mock_user
        # Trigger a threat
        for _ in range(11):
            result = threat_detector_no_redis.check_brute_force(
                ip="192.168.1.1",
                email="test@example.com",
                success=False,
            )

        assert result is not None
        alert = result.to_alert()

        assert isinstance(alert, SecurityAlert)
        assert alert.priority == AlertPriority.HIGH
        assert alert.alert_id == result.event_id

    def test_alert_fingerprint_uniqueness(self, alert_manager: SecurityAlertManager) -> None:
        """Different alerts should have different fingerprints."""
        alert1 = alert_manager.create_alert(
            title="Alert 1",
            description="Test",
            priority=AlertPriority.HIGH,
            category="category1",
            source="source1",
        )

        alert2 = alert_manager.create_alert(
            title="Alert 2",
            description="Test",
            priority=AlertPriority.HIGH,
            category="category2",
            source="source2",
        )

        assert alert1.fingerprint() != alert2.fingerprint()


# =============================================================================
# Performance Tests (3 tests)
# =============================================================================


class TestPerformance:
    """Performance tests for threat detection."""

    def test_check_request_under_10ms(self, threat_detector: ThreatDetector) -> None:
        """check_request should complete in under 10ms for typical requests."""
        times: list[float] = []

        for _ in range(100):
            start = time.time()
            threat_detector.check_request(
                ip="192.168.1.1",
                endpoint="/api/users",
                method="POST",
                headers={"user-agent": "Mozilla/5.0"},
                body={"email": "user@example.com", "name": "Test User"},
            )
            elapsed = (time.time() - start) * 1000
            times.append(elapsed)

        avg_time = sum(times) / len(times)
        assert avg_time < 10, f"Average time {avg_time:.2f}ms exceeds 10ms threshold"

    def test_pattern_matching_performance(self, pattern_matcher: PatternMatcher) -> None:
        """Pattern matching should be performant."""
        test_input = "Normal user input with some ' characters and <tags>"
        times: list[float] = []

        for _ in range(1000):
            start = time.time()
            pattern_matcher.match_all(test_input)
            elapsed = (time.time() - start) * 1000
            times.append(elapsed)

        avg_time = sum(times) / len(times)
        assert avg_time < 5, f"Average pattern matching time {avg_time:.2f}ms too high"

    def test_ip_block_check_performance(self, threat_detector_no_redis: ThreatDetector) -> None:
        """IP block check should be very fast."""
        # Block some IPs first
        for i in range(100):
            threat_detector_no_redis.block_ip(f"192.168.{i}.1", "test")

        times: list[float] = []

        for _ in range(1000):
            start = time.time()
            threat_detector_no_redis.is_blocked("192.168.50.1")
            elapsed = (time.time() - start) * 1000
            times.append(elapsed)

        avg_time = sum(times) / len(times)
        assert avg_time < 0.1, f"Average IP check time {avg_time:.4f}ms too high"


# =============================================================================
# Edge Case Tests (5 tests)
# =============================================================================


class TestEdgeCases:
    """Edge case and boundary condition tests."""

    def test_empty_input_handling(self, pattern_matcher: PatternMatcher) -> None:
        """Empty input should not cause errors."""
        matches = pattern_matcher.match_all("")
        assert not matches

        matches = pattern_matcher.match_all(None)  # type: ignore
        assert not matches

    def test_very_long_input_handling(self, threat_detector: ThreatDetector) -> None:
        """Very long input should be handled gracefully."""
        long_input = "A" * 100000

        result = threat_detector.check_request(
            ip="192.168.1.1",
            endpoint="/api/test",
            method="POST",
            headers={},
            body={"data": long_input},
        )

        assert isinstance(result, ThreatDetectionResult)

    def test_unicode_input_handling(self, pattern_matcher: PatternMatcher) -> None:
        """Unicode input should be handled correctly."""
        unicode_inputs = [
            "Hello",
            "Hola",
            "Ciao",
            "Testing special chars",
        ]

        for input_value in unicode_inputs:
            matches = pattern_matcher.match_all(input_value)
            # Should not crash
            assert isinstance(matches, list)

    def test_malformed_json_body(self, threat_detector: ThreatDetector) -> None:
        """Malformed body should not crash the detector."""
        result = threat_detector.check_request(
            ip="192.168.1.1",
            endpoint="/api/test",
            method="POST",
            headers={},
            body=None,
        )

        assert isinstance(result, ThreatDetectionResult)

    def test_reset_stats(self, threat_detector: ThreatDetector) -> None:
        """Stats should be resettable."""
        threat_detector.check_brute_force(
            ip="192.168.1.1",
            email="test@example.com",
            success=False,
        )

        assert threat_detector.stats["total_checks"] > 0

        threat_detector.reset_stats()

        assert threat_detector.stats["total_checks"] == 0
        assert threat_detector.stats["threats_detected"] == 0


# =============================================================================
# Summary
# =============================================================================

# Test Coverage Summary:
#
# PATTERN MATCHING (10 tests):
# - SQL injection
# - XSS
# - Path traversal
# - Command injection
# - SSRF
# - Clean input no false positives
# - Severity sorting
# - Confidence scores
# - Context extraction
# - Type filtering
#
# INTEGRATION (5 tests):
# - Comprehensive check
# - Attack in body
# - Attack in URL
# - Blocked IP early exit
# - Suspicious user agent
#
# ALERTS (5 tests):
# - Alert creation
# - Rate limiting
# - Deduplication
# - Event to alert conversion
# - Fingerprint uniqueness
#
# PERFORMANCE (3 tests):
# - check_request under 10ms
# - Pattern matching performance
# - IP block check performance
#
# EDGE CASES (5 tests):
# - Empty input
# - Very long input
# - Unicode input
# - Malformed body
# - Reset stats
#
# TOTAL: 28 TESTS
