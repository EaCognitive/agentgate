"""
Threat detector configuration and internal state management.

Provides data structures for configuration, state management, and statistics.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .alerts import SecurityAlertManager
from .alerting_factory import build_alert_manager_from_environment
from .threat_patterns import PatternMatcher

if TYPE_CHECKING:
    from redis import Redis


@dataclass
class _ThreatDetectorIPState:
    """IP-related state for threat detector."""

    blocked_ips_expiry: dict[str, tuple[float, str]] = field(default_factory=dict)
    suspicious_ips: set[str] = field(default_factory=set)

    @property
    def blocked_ips(self) -> set[str]:
        """Get currently blocked IPs, pruning expired entries."""
        now = time.time()
        expired = [ip for ip, (expiry, _reason) in self.blocked_ips_expiry.items() if expiry <= now]
        for ip in expired:
            del self.blocked_ips_expiry[ip]
        return set(self.blocked_ips_expiry.keys())


@dataclass
class _ThreatDetectorUserState:
    """User tracking state for threat detector."""

    user_known_ips: dict[int, set[str]] = field(default_factory=lambda: defaultdict(set))


@dataclass
class ThreatDetectorState:
    """In-memory state for threat detector."""

    failed_logins: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list))
    request_counts: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list))
    ip_state: _ThreatDetectorIPState = field(default_factory=_ThreatDetectorIPState)
    user_state: _ThreatDetectorUserState = field(default_factory=_ThreatDetectorUserState)

    # Backwards compatibility properties
    @property
    def blocked_ips(self) -> set[str]:
        """Get blocked IPs from ip_state."""
        return self.ip_state.blocked_ips

    @blocked_ips.setter
    def blocked_ips(self, value: set[str]) -> None:
        """Set blocked IPs in ip_state from a plain set.

        Converts each IP to a far-future expiry entry so they
        remain indefinitely blocked until explicitly unblocked.
        """
        far_future = time.time() + 86400 * 365 * 100
        self.ip_state.blocked_ips_expiry = {ip: (far_future, "legacy_set") for ip in value}

    @property
    def suspicious_ips(self) -> set[str]:
        """Get suspicious IPs from ip_state."""
        return self.ip_state.suspicious_ips

    @suspicious_ips.setter
    def suspicious_ips(self, value: set[str]) -> None:
        """Set suspicious IPs in ip_state."""
        self.ip_state.suspicious_ips = value

    @property
    def user_known_ips(self) -> dict[int, set[str]]:
        """Get user known IPs from user_state."""
        return self.user_state.user_known_ips

    @user_known_ips.setter
    def user_known_ips(self, value: dict[int, set[str]]) -> None:
        """Set user known IPs in user_state."""
        self.user_state.user_known_ips = value


@dataclass
class _ThreatDetectorConfig:
    """Configuration for threat detector."""

    enable_metrics: bool = True
    auto_block: bool = True


@dataclass
class _ThreatDetectorServices:
    """External services for threat detector."""

    redis_client: "Redis | None" = None
    alert_manager: SecurityAlertManager | None = None
    pattern_matcher: PatternMatcher | None = None

    def __post_init__(self):
        """Set defaults for services."""
        if self.alert_manager is None:
            self.alert_manager = build_alert_manager_from_environment()
        if self.pattern_matcher is None:
            self.pattern_matcher = PatternMatcher()


@dataclass
class _ThreatDetectorStats:
    """Statistics for threat detector."""

    total_checks: int = 0
    threats_detected: int = 0
    ips_blocked: int = 0
    brute_force_detected: int = 0
    injection_detected: int = 0


__all__ = [
    "ThreatDetectorState",
    "_ThreatDetectorConfig",
    "_ThreatDetectorServices",
    "_ThreatDetectorStats",
    "_ThreatDetectorIPState",
    "_ThreatDetectorUserState",
]
