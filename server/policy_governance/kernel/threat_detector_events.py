"""
Threat detection event models and utilities.

Provides data structures for threat events and their properties.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

from .alerts import AlertPriority, SecurityAlert, AlertUserContext, AlertEventInfo, AlertContentInfo
from .threat_definitions import ThreatSeverity, ThreatType, ThreatContext


# Alias for backwards compatibility
ThreatEventContext = ThreatContext


@dataclass
class ThreatEventIdentification:
    """Event identification information."""

    event_id: str
    event_type: ThreatType
    severity: ThreatSeverity
    timestamp: float


@dataclass
class ThreatEventPayload:
    """Event payload information."""

    ip_address: str
    details: dict[str, Any] = field(default_factory=dict)
    pattern_matches: list[dict[str, Any]] = field(default_factory=list)
    blocked: bool = False


@dataclass
class ThreatEvent:
    """
    Immutable record of a detected threat.

    Contains all context needed for investigation and response.
    """

    identification: ThreatEventIdentification
    payload: ThreatEventPayload = field(default_factory=lambda: ThreatEventPayload(ip_address=""))
    # Context (nested for composition)
    context: ThreatEventContext = field(default_factory=ThreatEventContext)

    # Backwards compatibility properties
    @property
    def event_id(self) -> str:
        """Get event_id from identification."""
        return self.identification.event_id

    @property
    def event_type(self) -> ThreatType:
        """Get event_type from identification."""
        return self.identification.event_type

    @property
    def severity(self) -> ThreatSeverity:
        """Get severity from identification."""
        return self.identification.severity

    @property
    def timestamp(self) -> float:
        """Get timestamp from identification."""
        return self.identification.timestamp

    @property
    def ip_address(self) -> str:
        """Get ip_address from payload."""
        return self.payload.ip_address

    @property
    def details(self) -> dict[str, Any]:
        """Get details from payload."""
        return self.payload.details

    @property
    def pattern_matches(self) -> list[dict[str, Any]]:
        """Get pattern_matches from payload."""
        return self.payload.pattern_matches

    @property
    def blocked(self) -> bool:
        """Get blocked from payload."""
        return self.payload.blocked

    @property
    def user_id(self) -> int | None:
        """Get user_id from context."""
        return self.context.user_id

    @user_id.setter
    def user_id(self, value: int | None) -> None:
        """Set user_id in context."""
        self.context.user_id = value

    @property
    def user_email(self) -> str | None:
        """Get user_email from context."""
        return self.context.user_email

    @user_email.setter
    def user_email(self, value: str | None) -> None:
        """Set user_email in context."""
        self.context.user_email = value

    @property
    def endpoint(self) -> str | None:
        """Get endpoint from context."""
        return self.context.endpoint

    @endpoint.setter
    def endpoint(self, value: str | None) -> None:
        """Set endpoint in context."""
        self.context.endpoint = value

    @property
    def user_agent(self) -> str | None:
        """Get user_agent from context."""
        return self.context.user_agent

    @user_agent.setter
    def user_agent(self, value: str | None) -> None:
        """Set user_agent in context."""
        self.context.user_agent = value

    @property
    def action_taken(self) -> str | None:
        """Get action_taken from context."""
        return self.context.action_taken

    @action_taken.setter
    def action_taken(self, value: str | None) -> None:
        """Set action_taken in context."""
        self.context.action_taken = value

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        # Flatten nested structures for backwards compatibility
        identification = data.pop("identification")
        payload = data.pop("payload")
        context = data.pop("context")
        data.update(identification)
        data.update(payload)
        data.update(context)
        data["event_type"] = self.event_type.value
        data["severity"] = self.severity.value
        data["timestamp_iso"] = datetime.fromtimestamp(self.timestamp, tz=timezone.utc).isoformat()
        return data

    def to_alert(self) -> SecurityAlert:
        """Convert to SecurityAlert for notification."""
        priority_map = {
            ThreatSeverity.LOW: AlertPriority.LOW,
            ThreatSeverity.MEDIUM: AlertPriority.MEDIUM,
            ThreatSeverity.HIGH: AlertPriority.HIGH,
            ThreatSeverity.CRITICAL: AlertPriority.CRITICAL,
        }

        description = self.details.get("description", "")
        if not description:
            description = f"Detected {self.event_type.value} from {self.ip_address}"

        return SecurityAlert(
            event_info=AlertEventInfo(
                alert_id=self.event_id,
                timestamp=self.timestamp,
                priority=priority_map[self.severity],
            ),
            content_info=AlertContentInfo(
                title=f"Threat Detected: {self.event_type.value}",
                description=description,
                source="threat_detector",
                category=self.event_type.value,
            ),
            ip_address=self.ip_address,
            details=self.details,
            user_context=AlertUserContext(
                user_id=self.context.user_id,
                user_email=self.context.user_email,
            ),
        )


__all__ = [
    "ThreatSeverity",
    "ThreatType",
    "ThreatEventContext",
    "ThreatEventIdentification",
    "ThreatEventPayload",
    "ThreatEvent",
]
