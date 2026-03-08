"""
Security alert management and notification system.

Provides multi-channel alert delivery for security events with:
- Priority-based routing
- Rate limiting to prevent alert fatigue
- Multiple delivery channels (webhook, log, email)
- Alert aggregation and deduplication

This module serves as the public API surface. Data models live
in ``alert_models``, and channel implementations live in
``alert_dispatch``. All symbols are re-exported here for full
backwards compatibility.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from collections import defaultdict
from typing import Any

from .alert_models import (
    AlertChannel,
    AlertContentInfo,
    AlertEventInfo,
    AlertMetadata,
    AlertPriority,
    AlertUserContext,
    RateLimitConfig,
    SecurityAlert,
)
from .alert_dispatch import (
    LogAlertChannel,
    SlackAlertChannel,
    WebhookAlertChannel,
)

logger = logging.getLogger(__name__)


class SecurityAlertManager:
    """
    Central manager for security alerts.

    Provides:
    - Multi-channel alert delivery
    - Rate limiting to prevent alert fatigue
    - Alert deduplication
    - Priority-based routing
    - Async and sync delivery modes
    """

    def __init__(
        self,
        channels: list[AlertChannel] | None = None,
        rate_limit: RateLimitConfig | None = None,
        dedup_window_seconds: float = 300.0,
    ):
        """
        Initialize alert manager.

        Args:
            channels: List of delivery channels.
            rate_limit: Rate limiting configuration.
            dedup_window_seconds: Deduplication window.
        """
        self._channels: list[AlertChannel] = channels or [LogAlertChannel()]
        self._rate_limit = rate_limit or RateLimitConfig()
        self._dedup_window = dedup_window_seconds

        # Rate limiting state
        self._alert_counts: dict[str, list[float]] = defaultdict(list)
        self._cooldown_until: dict[str, float] = {}

        # Deduplication state
        self._recent_fingerprints: dict[str, float] = {}

        # Statistics
        self._stats = {
            "total_alerts": 0,
            "alerts_sent": 0,
            "alerts_suppressed": 0,
            "alerts_deduplicated": 0,
        }

    @property
    def stats(self) -> dict[str, int]:
        """Get alert statistics."""
        return self._stats.copy()

    def add_channel(self, channel: AlertChannel) -> None:
        """Add a delivery channel."""
        self._channels.append(channel)

    def remove_channel(self, name: str) -> bool:
        """Remove a channel by name."""
        for i, channel in enumerate(self._channels):
            if channel.name == name:
                self._channels.pop(i)
                return True
        return False

    def _is_rate_limited(self, key: str) -> bool:
        """Check if alerts are rate limited for a key."""
        now = time.time()

        # Check cooldown
        if key in self._cooldown_until:
            if now < self._cooldown_until[key]:
                return True
            del self._cooldown_until[key]

        # Clean old entries
        cutoff = now - self._rate_limit.window_seconds
        self._alert_counts[key] = [t for t in self._alert_counts[key] if t > cutoff]

        # Check rate limit
        if len(self._alert_counts[key]) >= self._rate_limit.max_alerts_per_window:
            self._cooldown_until[key] = now + self._rate_limit.cooldown_seconds
            logger.warning(
                "Rate limit exceeded for %s, entering cooldown",
                key,
            )
            return True

        return False

    def _record_alert(self, key: str) -> None:
        """Record alert for rate limiting."""
        self._alert_counts[key].append(time.time())

    def _is_duplicate(self, alert: SecurityAlert) -> bool:
        """Check if alert is a duplicate."""
        fingerprint = alert.fingerprint()
        now = time.time()

        # Clean old fingerprints
        cutoff = now - self._dedup_window
        self._recent_fingerprints = {
            fp: ts for fp, ts in self._recent_fingerprints.items() if ts > cutoff
        }

        if fingerprint in self._recent_fingerprints:
            return True

        self._recent_fingerprints[fingerprint] = now
        return False

    def send_alert(self, alert: SecurityAlert) -> bool:
        """
        Send alert through all configured channels.

        Args:
            alert: Alert to send.

        Returns:
            True if sent to at least one channel.
        """
        self._stats["total_alerts"] += 1

        if self._is_duplicate(alert):
            self._stats["alerts_deduplicated"] += 1
            logger.debug(
                "Alert deduplicated: %s",
                alert.alert_id,
            )
            return False

        rate_key = f"{alert.category}:{alert.source}"
        if self._is_rate_limited(rate_key):
            self._stats["alerts_suppressed"] += 1
            logger.debug(
                "Alert rate limited: %s",
                alert.alert_id,
            )
            return False

        sent = False
        for channel in self._channels:
            try:
                if channel.send(alert):
                    sent = True
            except (
                OSError,
                RuntimeError,
                ValueError,
            ) as e:
                logger.error(
                    "Channel %s failed: %s",
                    channel.name,
                    e,
                )

        if sent:
            self._record_alert(rate_key)
            self._stats["alerts_sent"] += 1

        return sent

    async def send_alert_async(self, alert: SecurityAlert) -> bool:
        """
        Send alert asynchronously through all channels.

        Args:
            alert: Alert to send.

        Returns:
            True if sent to at least one channel.
        """
        self._stats["total_alerts"] += 1

        if self._is_duplicate(alert):
            self._stats["alerts_deduplicated"] += 1
            return False

        rate_key = f"{alert.category}:{alert.source}"
        if self._is_rate_limited(rate_key):
            self._stats["alerts_suppressed"] += 1
            return False

        tasks = []
        for channel in self._channels:
            if channel.supports_async:
                tasks.append(channel.send_async(alert))
            else:
                tasks.append(asyncio.to_thread(channel.send, alert))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        sent = any(r is True for r in results if not isinstance(r, Exception))

        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(
                    "Async channel %s failed: %s",
                    self._channels[i].name,
                    result,
                )

        if sent:
            self._record_alert(rate_key)
            self._stats["alerts_sent"] += 1

        return sent

    def create_alert(  # pylint: disable=too-many-arguments
        self,
        title: str,
        description: str,
        priority: AlertPriority,
        *,
        category: str,
        source: str,
        ip_address: str | None = None,
        user_id: int | None = None,
        user_email: str | None = None,
        details: dict[str, Any] | None = None,
        tags: list[str] | None = None,
    ) -> SecurityAlert:
        """
        Create a new security alert.

        Args:
            title: Alert title.
            description: Detailed description.
            priority: Alert priority.
            category: Threat category.
            source: Detection source.
            ip_address: Source IP address.
            user_id: Associated user ID.
            user_email: Associated user email.
            details: Additional alert details.
            tags: Alert tags.

        Returns:
            Configured SecurityAlert instance.
        """
        return SecurityAlert(
            event_info=AlertEventInfo(
                alert_id=(f"alert_{int(time.time())}_{secrets.token_hex(4)}"),
                timestamp=time.time(),
                priority=priority,
            ),
            content_info=AlertContentInfo(
                title=title,
                description=description,
                source=source,
                category=category,
            ),
            ip_address=ip_address,
            details=details or {},
            user_context=AlertUserContext(
                user_id=user_id,
                user_email=user_email,
                tags=tags or [],
            ),
        )


def send_security_alert(  # pylint: disable=too-many-arguments
    title: str,
    description: str,
    *,
    priority: AlertPriority = AlertPriority.HIGH,
    category: str = "security",
    source: str = "threat_detector",
    ip_address: str | None = None,
    user_id: int | None = None,
    user_email: str | None = None,
    details: dict[str, Any] | None = None,
    tags: list[str] | None = None,
) -> bool:
    """
    Send a security alert using the default manager.

    This is a convenience function for one-off alerts.
    For production use, configure a SecurityAlertManager.

    Args:
        title: Alert title.
        description: Alert description.
        priority: Alert priority (default: HIGH).
        category: Threat category.
        source: Detection source.
        ip_address: Source IP address.
        user_id: Associated user ID.
        user_email: Associated user email.
        details: Additional alert details.
        tags: Alert tags.

    Returns:
        True if alert was sent.
    """
    manager = SecurityAlertManager()
    alert = manager.create_alert(
        title=title,
        description=description,
        priority=priority,
        category=category,
        source=source,
        ip_address=ip_address,
        user_id=user_id,
        user_email=user_email,
        details=details,
        tags=tags,
    )
    return manager.send_alert(alert)


__all__ = [
    "AlertPriority",
    "AlertMetadata",
    "AlertUserContext",
    "AlertEventInfo",
    "AlertContentInfo",
    "SecurityAlert",
    "AlertChannel",
    "LogAlertChannel",
    "WebhookAlertChannel",
    "SlackAlertChannel",
    "RateLimitConfig",
    "SecurityAlertManager",
    "send_security_alert",
]
