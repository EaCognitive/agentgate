"""
Utility functions and helpers for threat detection.

Provides helper methods for:
- Request body, query, and header checking
- Pattern and severity mapping
- User agent detection
- State management for threat tracking
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING, cast

from .threat_patterns import PatternSeverity
from .threat_definitions import ThreatSeverity, ThreatType, ThreatContext

if TYPE_CHECKING:
    from redis import Redis

logger = logging.getLogger(__name__)


@dataclass
class RequestCheckResults:
    """Aggregated results from request threat checks."""

    threats: list[Any] = field(default_factory=list)
    should_block: bool = False


@dataclass
class ThreatDetectionResult:
    """Result of threat detection check."""

    is_threat: bool
    threats: list[Any] = field(default_factory=list)
    should_block: bool = False
    block_reason: str | None = None
    processing_time_ms: float = 0.0

    def get_highest_severity(self) -> str | None:
        """Get highest severity among detected threats."""
        if not self.threats:
            return None

        severity_order = [
            ThreatSeverity.CRITICAL,
            ThreatSeverity.HIGH,
            ThreatSeverity.MEDIUM,
            ThreatSeverity.LOW,
        ]

        for severity in severity_order:
            if any(t.severity == severity for t in self.threats):
                return severity

        return None


def pattern_to_threat_type(pattern_type: str) -> str:
    """Map pattern type to threat type."""
    mapping = {
        "injection": ThreatType.SQL_INJECTION,
        "xss": ThreatType.XSS,
        "traversal": ThreatType.PATH_TRAVERSAL,
        "ssrf": ThreatType.DATA_EXFILTRATION,
    }
    return mapping.get(pattern_type, ThreatType.SQL_INJECTION)


def pattern_to_threat_severity(pattern_severity: PatternSeverity) -> str:
    """Map pattern severity to threat severity."""
    mapping = {
        PatternSeverity.LOW: ThreatSeverity.LOW,
        PatternSeverity.MEDIUM: ThreatSeverity.MEDIUM,
        PatternSeverity.HIGH: ThreatSeverity.HIGH,
        PatternSeverity.CRITICAL: ThreatSeverity.CRITICAL,
    }
    return mapping[pattern_severity]


def is_suspicious_user_agent(user_agent: str) -> bool:
    """Check if user agent is suspicious."""
    if not user_agent:
        return True

    suspicious_patterns = [
        "curl",
        "wget",
        "python-requests",
        "sqlmap",
        "nikto",
        "burp",
        "nmap",
        "masscan",
        "zgrab",
        "scanner",
    ]

    ua_lower = user_agent.lower()
    return any(pattern in ua_lower for pattern in suspicious_patterns)


class StateManager:
    """Manager for threat detector state operations."""

    BRUTE_FORCE_WINDOW_SECONDS = 3600  # 1 hour

    def __init__(self, redis_client: Redis | None = None) -> None:
        """Initialize state manager with optional Redis client."""
        self._redis = redis_client

    def record_failed_login(
        self,
        ip: str,
        timestamp: float,
        failed_logins: dict[str, list[float]],
    ) -> int:
        """Record failed login and return count within window."""
        key = f"failed_logins:{ip}"
        window_start = timestamp - self.BRUTE_FORCE_WINDOW_SECONDS

        if self._redis:
            try:
                pipe = self._redis.pipeline()
                pipe.zremrangebyscore(key, "-inf", window_start)
                pipe.zadd(key, {str(timestamp): timestamp})
                pipe.zcard(key)
                pipe.expire(key, self.BRUTE_FORCE_WINDOW_SECONDS)
                results = pipe.execute()
                return int(results[2])
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.warning("Redis failed login record failed: %s", e)

        # Fallback to in-memory
        recent_logins = [t for t in failed_logins[ip] if t > window_start]
        failed_logins[ip] = recent_logins
        failed_logins[ip].append(timestamp)
        return len(failed_logins[ip])

    def clear_failed_logins(self, ip: str, failed_logins: dict[str, list[float]]) -> None:
        """Clear failed login count for IP."""
        key = f"failed_logins:{ip}"

        if self._redis:
            try:
                self._redis.delete(key)
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.warning("Redis clear failed: %s", e)

        failed_logins.pop(ip, None)

    def record_request(
        self,
        key: str,
        timestamp: float,
        request_counts: dict[str, list[float]],
    ) -> int:
        """Record request and return rate (per minute)."""
        redis_key = f"request_rate:{key}"
        window_start = timestamp - 60  # 1 minute window

        if self._redis:
            try:
                pipe = self._redis.pipeline()
                pipe.zremrangebyscore(redis_key, "-inf", window_start)
                pipe.zadd(redis_key, {str(timestamp): timestamp})
                pipe.zcard(redis_key)
                pipe.expire(redis_key, 120)
                results = pipe.execute()
                return int(results[2])
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.warning("Redis request rate failed: %s", e)

        # Fallback to in-memory
        recent_requests = [t for t in request_counts[key] if t > window_start]
        request_counts[key] = recent_requests
        request_counts[key].append(timestamp)
        return len(request_counts[key])

    def get_user_known_ips(
        self,
        user_id: int,
        user_known_ips: dict[int, set[str]],
    ) -> set[str]:
        """Get known IPs for a user."""
        key = f"user_ips:{user_id}"

        if self._redis:
            try:
                ips = self._redis.smembers(key)
                if ips:
                    return set(cast("list[str]", ips))
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.warning("Redis get user IPs failed: %s", e)

        return user_known_ips.get(user_id, set())

    def add_user_known_ip(
        self,
        user_id: int,
        ip: str,
        user_known_ips: dict[int, set[str]],
    ) -> None:
        """Add IP to user's known IPs."""
        key = f"user_ips:{user_id}"

        if self._redis:
            try:
                self._redis.sadd(key, ip)
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.warning("Redis add user IP failed: %s", e)

        user_known_ips[user_id].add(ip)


__all__ = [
    "ThreatContext",
    "ThreatDetectionResult",
    "RequestCheckResults",
    "ThreatSeverity",
    "ThreatType",
    "pattern_to_threat_type",
    "pattern_to_threat_severity",
    "is_suspicious_user_agent",
    "StateManager",
]
