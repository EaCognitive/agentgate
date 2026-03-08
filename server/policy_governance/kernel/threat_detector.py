"""
Production-grade real-time threat detection engine.

Provides comprehensive security monitoring including:
- Brute force attack detection
- Privilege escalation detection
- Data exfiltration detection
- Unusual location/behavior detection
- Pattern-based attack detection (SQLi, XSS, etc.)
- IP blocking and reputation tracking

Integrates with Redis for distributed state and Prometheus
for metrics. Detection strategies are decomposed into
composable sub-detectors (behavioral, input, IP blocking).
"""

from __future__ import annotations

import logging
import os
import secrets
import time
from importlib import import_module
from typing import TYPE_CHECKING, Any, Protocol

try:
    import redis
except ImportError:
    redis = None  # type: ignore[assignment]

try:
    from server.metrics import errors_total
except ImportError:
    errors_total = None  # type: ignore[assignment]

from .threat_patterns import PatternMatcher
from .alerts import SecurityAlertManager
from .threat_detector_events import (
    ThreatSeverity,
    ThreatType,
    ThreatEvent,
    ThreatEventContext,
    ThreatEventIdentification,
    ThreatEventPayload,
)
from .threat_detector_config import (
    ThreatDetectorState,
    _ThreatDetectorConfig,
    _ThreatDetectorServices,
    _ThreatDetectorStats,
)
from .threat_detector_utils import (
    RequestCheckResults,
    StateManager,
    ThreatDetectionResult,
)
from .detection_behavioral import BehavioralDetector
from .detection_input import InputDetector
from .detection_ip_blocking import IPBlockingManager

if TYPE_CHECKING:
    from redis import Redis


logger = logging.getLogger(__name__)


class UserProtocol(Protocol):
    """Protocol for user objects."""

    @property
    def id(self) -> int:
        """Return user ID."""
        raise NotImplementedError

    @property
    def email(self) -> str:
        """Return user email."""
        raise NotImplementedError

    @property
    def role(self) -> str:
        """Return user role."""
        raise NotImplementedError


class ThreatDetector:
    """
    Production-grade real-time threat detection engine.

    Composes specialized sub-detectors:
    - BehavioralDetector: brute force, escalation, exfil
    - InputDetector: SQLi, XSS, traversal scanning
    - IPBlockingManager: distributed IP blocking
    """

    # Thresholds for brute force detection
    BRUTE_FORCE_THRESHOLD_HIGH = 10
    BRUTE_FORCE_THRESHOLD_CRITICAL = 20
    BRUTE_FORCE_WINDOW_SECONDS = 3600  # 1 hour

    # Thresholds for data exfiltration
    HIGH_REQUEST_RATE_THRESHOLD = 100  # per minute
    LARGE_RESPONSE_SIZE_MB = 10

    # IP blocking duration
    DEFAULT_BLOCK_DURATION = 3600  # 1 hour

    def __init__(
        self,
        *,
        redis_client: "Redis | None" = None,
        alert_manager: SecurityAlertManager | None = None,
        pattern_matcher: PatternMatcher | None = None,
        enable_metrics: bool = True,
        auto_block: bool = True,
    ):
        """
        Initialize threat detector.

        Args:
            redis_client: Redis client for distributed state.
            alert_manager: Alert manager for notifications.
            pattern_matcher: Pattern matcher for detection.
            enable_metrics: Enable Prometheus metrics.
            auto_block: Auto block IPs on critical threats.
        """
        self._config = _ThreatDetectorConfig(
            enable_metrics=enable_metrics,
            auto_block=auto_block,
        )

        self._services = _ThreatDetectorServices(
            redis_client=redis_client,
            alert_manager=alert_manager,
            pattern_matcher=pattern_matcher,
        )

        self._state = ThreatDetectorState()
        self._state_manager = StateManager(self._services.redis_client)
        self._stats_obj = _ThreatDetectorStats()

        # Compose sub-detectors
        self._behavioral = BehavioralDetector()
        self._input = InputDetector()

        if self._services.redis_client is None:
            self._init_redis_from_env()

        self._state_manager = StateManager(self._services.redis_client)

        # IP blocking with current Redis state
        self._ip_blocking = IPBlockingManager(self._state, self._services.redis_client)

    # -- Backwards-compatible property accessors --

    @property
    def _redis(self) -> "Redis | None":
        """Get Redis client from services."""
        return self._services.redis_client

    @_redis.setter
    def _redis(self, value: "Redis | None") -> None:
        """Set Redis client in services."""
        self._services.redis_client = value

    @property
    def _alert_manager(self) -> SecurityAlertManager:
        """Get alert manager from services."""
        manager = self._services.alert_manager
        if manager is None:  # pragma: no cover - __post_init__ sets this
            raise RuntimeError("Threat detector alert manager is unavailable")
        return manager

    @property
    def _pattern_matcher(self) -> PatternMatcher:
        """Get pattern matcher from services."""
        matcher = self._services.pattern_matcher
        if matcher is None:  # pragma: no cover - __post_init__ sets this
            raise RuntimeError("Threat detector pattern matcher is unavailable")
        return matcher

    @property
    def _enable_metrics(self) -> bool:
        """Get enable_metrics from config."""
        return self._config.enable_metrics

    @property
    def _auto_block(self) -> bool:
        """Get auto_block from config."""
        return self._config.auto_block

    @property
    def _stats(self) -> dict[str, int]:
        """Get stats as dict for backwards compat."""
        return {
            "total_checks": (self._stats_obj.total_checks),
            "threats_detected": (self._stats_obj.threats_detected),
            "ips_blocked": (self._stats_obj.ips_blocked),
            "brute_force_detected": (self._stats_obj.brute_force_detected),
            "injection_detected": (self._stats_obj.injection_detected),
        }

    @_stats.setter
    def _stats(self, value: dict[str, int]) -> None:
        """Set stats from dict."""
        if isinstance(value, dict):
            self._stats_obj.total_checks = value.get("total_checks", 0)
            self._stats_obj.threats_detected = value.get("threats_detected", 0)
            self._stats_obj.ips_blocked = value.get("ips_blocked", 0)
            self._stats_obj.brute_force_detected = value.get("brute_force_detected", 0)
            self._stats_obj.injection_detected = value.get("injection_detected", 0)

    @property
    def _blocked_ips(self) -> set[str]:
        """Backwards-compatible accessor."""
        return self._state.blocked_ips

    @_blocked_ips.setter
    def _blocked_ips(self, value: set[str]) -> None:
        """Backwards-compatible setter."""
        self._state.blocked_ips = value

    @property
    def _failed_logins(
        self,
    ) -> dict[str, list[float]]:
        """Backwards-compatible accessor."""
        return self._state.failed_logins

    @_failed_logins.setter
    def _failed_logins(self, value: dict[str, list[float]]) -> None:
        """Backwards-compatible setter."""
        self._state.failed_logins = value

    @property
    def _user_known_ips(
        self,
    ) -> dict[int, set[str]]:
        """Backwards-compatible accessor."""
        return self._state.user_known_ips

    @_user_known_ips.setter
    def _user_known_ips(self, value: dict[int, set[str]]) -> None:
        """Backwards-compatible setter."""
        self._state.user_known_ips = value

    # -- Internal helpers --

    def _init_redis_from_env(self) -> None:
        """Initialize Redis from environment variables."""
        if redis is None:
            return
        redis_host = os.getenv("REDIS_HOST")
        if redis_host:
            try:
                self._services.redis_client = redis.Redis(
                    host=redis_host,
                    port=int(os.getenv("REDIS_PORT", "6379")),
                    db=int(os.getenv("REDIS_DB", "0")),
                    password=os.getenv("REDIS_PASSWORD"),
                    decode_responses=True,
                )
                self._services.redis_client.ping()
                logger.info("Connected to Redis for threat detection")
            # pylint: disable-next=broad-exception-caught
            except Exception as e:
                logger.warning(
                    "Redis connection failed, using in-memory state: %s",
                    e,
                )
                self._services.redis_client = None

    def _increment_stat(self, key: str, value: int = 1) -> None:
        """Increment a statistic."""
        if key == "total_checks":
            self._stats_obj.total_checks += value
        elif key == "threats_detected":
            self._stats_obj.threats_detected += value
        elif key == "ips_blocked":
            self._stats_obj.ips_blocked += value
        elif key == "brute_force_detected":
            self._stats_obj.brute_force_detected += value
        elif key == "injection_detected":
            self._stats_obj.injection_detected += value

    def _generate_event_id(self) -> str:
        """Generate unique event ID."""
        return f"threat_{int(time.time())}_{secrets.token_hex(4)}"

    def _record_metric(
        self,
        metric_name: str,
        value: float = 1.0,
        tags: dict[str, str] | None = None,
    ) -> None:
        """Record metric to monitoring system."""
        if not self._enable_metrics:
            return

        try:
            datadog_module = import_module("datadog")
            statsd = getattr(datadog_module, "statsd", None)
            if statsd is None:
                raise AttributeError("datadog.statsd unavailable")

            full_name = f"security.threat.{metric_name}"
            statsd_tags = [f"{k}:{v}" for k, v in tags.items()] if tags else None
            if isinstance(value, int) or value == 1.0:
                statsd.increment(full_name, tags=statsd_tags)
            else:
                statsd.gauge(
                    full_name,
                    value,
                    tags=statsd_tags,
                )
        except (
            ImportError,
            AttributeError,
            TypeError,
        ):
            pass

        try:
            if errors_total is not None and "blocked" in metric_name:
                errors_total.labels(error_type="ip_blocked").inc()
        except (
            AttributeError,
            TypeError,
        ):
            pass

    # -- Behavioral detection (delegated) --

    def check_brute_force(
        self,
        ip: str,
        email: str,
        success: bool,
        *,
        user_agent: str | None = None,
    ) -> ThreatEvent | None:
        """Detect brute force login attempts."""
        return self._behavioral.check_brute_force(
            self,
            ip,
            email,
            success,
            user_agent=user_agent,
        )

    def check_privilege_escalation(
        self,
        user: UserProtocol,
        action: str,
        *,
        target_role: str | None = None,
        ip: str | None = None,
    ) -> ThreatEvent | None:
        """Detect privilege escalation attempts."""
        return self._behavioral.check_privilege_escalation(
            self,
            user,
            action,
            target_role=target_role,
            ip=ip,
        )

    def check_data_exfiltration(
        self,
        user: UserProtocol,
        endpoint: str,
        response_size: int,
        *,
        ip: str | None = None,
    ) -> ThreatEvent | None:
        """Detect unusual data access patterns."""
        return self._behavioral.check_data_exfiltration(
            self,
            user,
            endpoint,
            response_size,
            ip=ip,
        )

    def check_new_location(
        self,
        user: UserProtocol,
        ip: str,
        user_agent: str,
    ) -> ThreatEvent | None:
        """Detect login from unusual location."""
        return self._behavioral.check_new_location(self, user, ip, user_agent)

    # -- Input detection (delegated) --

    def _build_input_attack_event(
        self,
        ip: str,
        field_name: str,
        match: Any,
        *,
        user_id: int | None,
        user_email: str | None,
    ) -> tuple[ThreatEvent, bool]:
        """Build threat event for input attack match."""
        return self._input.build_input_attack_event(
            self,
            ip,
            field_name,
            match,
            user_id=user_id,
            user_email=user_email,
        )

    def check_input_attacks(
        self,
        value: str,
        field_name: str,
        ip: str,
        *,
        user_id: int | None = None,
        user_email: str | None = None,
    ) -> ThreatDetectionResult:
        """Check input for attack patterns."""
        return self._input.check_input_attacks(
            self,
            value,
            field_name,
            ip,
            user_id=user_id,
            user_email=user_email,
        )

    def _check_request_body(
        self,
        body: dict[str, Any],
        ip: str,
        user_id: int | None,
        user_email: str | None,
    ) -> tuple[list[ThreatEvent], bool]:
        """Check request body for attack patterns."""
        return self._input.check_request_body(
            self,
            body,
            ip,
            user_id=user_id,
            user_email=user_email,
        )

    def _check_request_query(
        self,
        endpoint: str,
        ip: str,
        user_id: int | None,
        user_email: str | None,
    ) -> tuple[list[ThreatEvent], bool]:
        """Check query params for attack patterns."""
        return self._input.check_request_query(
            self,
            endpoint,
            ip,
            user_id=user_id,
            user_email=user_email,
        )

    def _check_request_headers(
        self,
        headers: dict[str, str],
        ip: str,
        user_id: int | None,
        user_email: str | None,
    ) -> list[ThreatEvent]:
        """Check headers for suspicious patterns."""
        return self._input.check_request_headers(
            self,
            headers,
            ip,
            user_id=user_id,
            user_email=user_email,
        )

    # pylint: disable-next=too-many-positional-arguments
    def check_request(
        self,
        ip: str,
        endpoint: str,
        method: str,
        headers: dict[str, str],
        body: dict[str, Any] | None = None,
        user_id: int | None = None,
        user_email: str | None = None,
    ) -> ThreatDetectionResult:
        """Comprehensive threat check for HTTP request."""
        del method  # Reserved for future use
        start_time = time.time()
        self._increment_stat("total_checks")

        if self.is_blocked(ip):
            return ThreatDetectionResult(
                is_threat=True,
                threats=[],
                should_block=True,
                block_reason="ip_blocked",
                processing_time_ms=((time.time() - start_time) * 1000),
            )

        result = self._aggregate_request_threats(
            body,
            endpoint,
            headers,
            ip,
            user_id=user_id,
            user_email=user_email,
        )

        processing_time = (time.time() - start_time) * 1000

        return ThreatDetectionResult(
            is_threat=len(result.threats) > 0,
            threats=result.threats,
            should_block=result.should_block,
            block_reason=("threat_detected" if result.should_block else None),
            processing_time_ms=processing_time,
        )

    def _aggregate_request_threats(
        self,
        body: dict[str, Any] | None,
        endpoint: str,
        headers: dict[str, str],
        ip: str,
        *,
        user_id: int | None,
        user_email: str | None,
    ) -> RequestCheckResults:
        """Aggregate threats from request components."""
        return self._input.aggregate_request_threats(
            self,
            body=body,
            endpoint=endpoint,
            headers=headers,
            ip=ip,
            user_id=user_id,
            user_email=user_email,
        )

    # -- IP Blocking (delegated) --

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked."""
        return self._ip_blocking.is_blocked(ip)

    def block_ip(
        self,
        ip: str,
        reason: str,
        duration: int = DEFAULT_BLOCK_DURATION,
    ) -> None:
        """Block an IP address for a given duration."""
        self._ip_blocking.block_ip(ip, reason, duration)
        self._increment_stat("ips_blocked")
        self._record_metric("ip_blocked", tags={"reason": reason})

    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address."""
        return self._ip_blocking.unblock_ip(ip)

    def get_blocked_ips(self) -> set[str]:
        """Get all currently blocked IPs."""
        return self._ip_blocking.get_blocked_ips()

    def get_blocked_ip_details(
        self,
    ) -> dict[str, dict]:
        """Get details for all blocked IPs."""
        return self._ip_blocking.get_blocked_ip_details()

    # -- State Management Helpers --

    def _record_failed_login(self, ip: str, timestamp: float) -> int:
        """Record failed login and return count."""
        return self._state_manager.record_failed_login(ip, timestamp, self._state.failed_logins)

    def _clear_failed_logins(self, ip: str) -> None:
        """Clear failed login count for IP."""
        self._state_manager.clear_failed_logins(ip, self._state.failed_logins)

    def _record_request(self, key: str, timestamp: float) -> int:
        """Record request and return rate."""
        return self._state_manager.record_request(key, timestamp, self._state.request_counts)

    def _get_user_known_ips(self, user_id: int) -> set[str]:
        """Get known IPs for a user."""
        return self._state_manager.get_user_known_ips(user_id, self._state.user_known_ips)

    def _add_user_known_ip(self, user_id: int, ip: str) -> None:
        """Add IP to user's known IPs."""
        self._state_manager.add_user_known_ip(user_id, ip, self._state.user_known_ips)

    # -- Utility Methods --

    def _send_alert(self, event: ThreatEvent) -> None:
        """Send security alert for threat event."""
        if event.severity in (
            ThreatSeverity.HIGH,
            ThreatSeverity.CRITICAL,
        ):
            alert = event.to_alert()
            self._alert_manager.send_alert(alert)

    @property
    def alert_stats(self) -> dict[str, int]:
        """Get alert manager statistics."""
        return self._alert_manager.stats

    @property
    def stats(self) -> dict[str, int]:
        """Get detector statistics."""
        return self._stats.copy()

    def reset_stats(self) -> None:
        """Reset statistics counters."""
        self._stats_obj.total_checks = 0
        self._stats_obj.threats_detected = 0
        self._stats_obj.ips_blocked = 0
        self._stats_obj.brute_force_detected = 0
        self._stats_obj.injection_detected = 0


__all__ = [
    "ThreatDetectionResult",
    "ThreatDetector",
    # Re-exported for backwards compatibility
    "ThreatSeverity",
    "ThreatType",
    "ThreatEvent",
    "ThreatEventContext",
    "ThreatEventIdentification",
    "ThreatEventPayload",
]
