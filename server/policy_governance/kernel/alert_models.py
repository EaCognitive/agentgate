"""
Security alert data models and protocols.

Provides core data structures for the alert system:
- AlertPriority: Priority levels for routing decisions
- SecurityAlert: Alert payload with event, content, and user context
- AlertChannel: Protocol for delivery channel implementations
- Supporting dataclasses for structured alert composition
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol


class AlertPriority(str, Enum):
    """Alert priority levels for routing decisions."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AlertMetadata:
    """Metadata for security alerts (user context)."""

    user_id: int | None = None
    user_email: str | None = None
    tags: list[str] = field(default_factory=list)
    related_events: list[str] = field(default_factory=list)


@dataclass
class AlertUserContext:
    """User context information for security alerts."""

    user_id: int | None = None
    user_email: str | None = None
    tags: list[str] = field(default_factory=list)
    related_events: list[str] = field(default_factory=list)


@dataclass
class AlertOptions:
    """Optional parameters for alert creation."""

    ip_address: str | None = None
    user_id: int | None = None
    user_email: str | None = None
    details: dict[str, Any] | None = None
    tags: list[str] | None = None


@dataclass
class AlertEventInfo:
    """Event information for security alerts."""

    alert_id: str
    timestamp: float
    priority: AlertPriority


@dataclass
class AlertContentInfo:
    """Content information for security alerts."""

    title: str
    description: str
    source: str
    category: str


@dataclass
class SecurityAlert:
    """
    Security alert payload.

    Contains all information needed for alert routing
    and display, composed from event, content, and user
    context sub-structures.
    """

    # Event identification and priority
    event_info: AlertEventInfo
    # Alert content
    content_info: AlertContentInfo
    # Network information
    ip_address: str | None = None
    # Additional details
    details: dict[str, Any] = field(default_factory=dict)
    # User context (nested for composition)
    user_context: AlertUserContext = field(default_factory=AlertUserContext)

    # Backwards compatibility properties
    @property
    def alert_id(self) -> str:
        """Get alert_id from event_info."""
        return self.event_info.alert_id

    @property
    def timestamp(self) -> float:
        """Get timestamp from event_info."""
        return self.event_info.timestamp

    @property
    def priority(self) -> AlertPriority:
        """Get priority from event_info."""
        return self.event_info.priority

    @property
    def title(self) -> str:
        """Get title from content_info."""
        return self.content_info.title

    @property
    def description(self) -> str:
        """Get description from content_info."""
        return self.content_info.description

    @property
    def source(self) -> str:
        """Get source from content_info."""
        return self.content_info.source

    @property
    def category(self) -> str:
        """Get category from content_info."""
        return self.content_info.category

    @property
    def user_id(self) -> int | None:
        """Get user_id from context."""
        return self.user_context.user_id

    @property
    def user_email(self) -> str | None:
        """Get user_email from context."""
        return self.user_context.user_email

    @property
    def tags(self) -> list[str]:
        """Get tags from context."""
        return self.user_context.tags

    @property
    def related_events(self) -> list[str]:
        """Get related_events from context."""
        return self.user_context.related_events

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        # Flatten nested structures for backwards compat
        event_info = data.pop("event_info")
        content_info = data.pop("content_info")
        user_context = data.pop("user_context")
        data.update(event_info)
        data.update(content_info)
        data.update(user_context)
        data["priority"] = self.priority.value
        data["timestamp_iso"] = datetime.fromtimestamp(self.timestamp, tz=timezone.utc).isoformat()
        return data

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), default=str)

    def fingerprint(self) -> str:
        """
        Generate fingerprint for deduplication.

        Returns:
            Hash string identifying similar alerts.
        """
        key = (
            f"{self.content_info.category}"
            f":{self.content_info.source}"
            f":{self.ip_address}"
            f":{self.user_context.user_id}"
        )
        return hashlib.sha256(key.encode()).hexdigest()[:16]


class AlertChannel(Protocol):
    """Protocol for alert delivery channels."""

    @property
    def name(self) -> str:
        """Channel identifier."""
        raise NotImplementedError

    @property
    def supports_async(self) -> bool:
        """Whether channel supports async delivery."""
        raise NotImplementedError

    def send(self, alert: SecurityAlert) -> bool:
        """
        Send alert synchronously.

        Args:
            alert: Alert to send.

        Returns:
            True if delivery succeeded.
        """
        raise NotImplementedError

    async def send_async(self, alert: SecurityAlert) -> bool:
        """
        Send alert asynchronously.

        Args:
            alert: Alert to send.

        Returns:
            True if delivery succeeded.
        """
        raise NotImplementedError


@dataclass
class RateLimitConfig:
    """Configuration for alert rate limiting."""

    window_seconds: float = 60.0
    max_alerts_per_window: int = 10
    cooldown_seconds: float = 300.0
    max_alerts_during_cooldown: int = 1


__all__ = [
    "AlertPriority",
    "AlertMetadata",
    "AlertUserContext",
    "AlertOptions",
    "AlertEventInfo",
    "AlertContentInfo",
    "SecurityAlert",
    "AlertChannel",
    "RateLimitConfig",
]
