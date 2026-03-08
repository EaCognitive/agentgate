"""
Alert delivery channel implementations.

Provides concrete channel implementations for security alert delivery:
- LogAlertChannel: Structured logging output
- WebhookAlertChannel: HTTP webhook delivery
- SlackAlertChannel: Slack-formatted webhook delivery

Each channel implements the AlertChannel protocol defined in alerts.py.
"""

from __future__ import annotations

import logging
from typing import Any
from collections.abc import Callable

import httpx

from .alert_models import (
    AlertPriority,
    SecurityAlert,
)

logger = logging.getLogger(__name__)


class LogAlertChannel:
    """Alert channel that writes to structured logging."""

    def __init__(
        self,
        logger_name: str = "security.alerts",
        min_priority: AlertPriority = AlertPriority.LOW,
    ):
        """
        Initialize log channel.

        Args:
            logger_name: Logger name to use.
            min_priority: Minimum priority to log.
        """
        self._logger = logging.getLogger(logger_name)
        self._min_priority = min_priority
        self._name = "log"

    @property
    def name(self) -> str:
        """Get the channel name."""
        return self._name

    @property
    def supports_async(self) -> bool:
        """Check if channel supports async delivery."""
        return True

    def _should_send(self, alert: SecurityAlert) -> bool:
        """Check if alert meets minimum priority."""
        priority_order = [
            AlertPriority.LOW,
            AlertPriority.MEDIUM,
            AlertPriority.HIGH,
            AlertPriority.CRITICAL,
        ]
        return priority_order.index(alert.priority) >= priority_order.index(self._min_priority)

    def _get_log_level(self, priority: AlertPriority) -> int:
        """Map priority to log level."""
        mapping = {
            AlertPriority.LOW: logging.INFO,
            AlertPriority.MEDIUM: logging.WARNING,
            AlertPriority.HIGH: logging.ERROR,
            AlertPriority.CRITICAL: logging.CRITICAL,
        }
        return mapping[priority]

    def send(self, alert: SecurityAlert) -> bool:
        """Send alert to log."""
        if not self._should_send(alert):
            return True

        level = self._get_log_level(alert.priority)
        self._logger.log(
            level,
            "Security Alert: %s - %s",
            alert.title,
            alert.description,
            extra={
                "alert_id": alert.alert_id,
                "priority": alert.priority.value,
                "category": alert.category,
                "source": alert.source,
                "ip_address": alert.ip_address,
                "user_id": alert.user_id,
                "details": alert.details,
            },
        )
        return True

    async def send_async(self, alert: SecurityAlert) -> bool:
        """Async send (delegates to sync for logging)."""
        return self.send(alert)


class WebhookAlertChannel:
    """Alert channel that sends to HTTP webhooks."""

    def __init__(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
        min_priority: AlertPriority = AlertPriority.MEDIUM,
        transform: (Callable[[SecurityAlert], dict[str, Any]] | None) = None,
    ):
        """
        Initialize webhook channel.

        Args:
            url: Webhook URL to POST to.
            headers: Additional headers to include.
            timeout: Request timeout in seconds.
            min_priority: Minimum priority to send.
            transform: Optional transform for alert payload.
        """
        self._url = url
        self._headers = headers or {}
        self._timeout = timeout
        self._min_priority = min_priority
        self._transform = transform
        self._name = f"webhook:{url[:50]}"

    @property
    def name(self) -> str:
        """Get the channel name."""
        return self._name

    @property
    def supports_async(self) -> bool:
        """Check if channel supports async delivery."""
        return True

    def _should_send(self, alert: SecurityAlert) -> bool:
        """Check if alert meets minimum priority."""
        priority_order = [
            AlertPriority.LOW,
            AlertPriority.MEDIUM,
            AlertPriority.HIGH,
            AlertPriority.CRITICAL,
        ]
        return priority_order.index(alert.priority) >= priority_order.index(self._min_priority)

    def _prepare_payload(self, alert: SecurityAlert) -> dict[str, Any]:
        """Prepare webhook payload."""
        if self._transform:
            return self._transform(alert)
        return alert.to_dict()

    def send(self, alert: SecurityAlert) -> bool:
        """Send alert synchronously."""
        if not self._should_send(alert):
            return True

        try:
            payload = self._prepare_payload(alert)
            headers = {
                "Content-Type": "application/json",
                **self._headers,
            }

            with httpx.Client(timeout=self._timeout) as client:
                response = client.post(
                    self._url,
                    json=payload,
                    headers=headers,
                )
                response.raise_for_status()
                return True

        except ImportError:
            logger.warning("httpx not installed, webhook alerts disabled")
            return False
        except (
            httpx.RequestError,
            httpx.HTTPStatusError,
        ) as e:
            logger.error("Failed to send webhook alert: %s", e)
            return False
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error("Failed to send webhook alert: %s", e)
            return False

    async def send_async(self, alert: SecurityAlert) -> bool:
        """Send alert asynchronously."""
        if not self._should_send(alert):
            return True

        try:
            payload = self._prepare_payload(alert)
            headers = {
                "Content-Type": "application/json",
                **self._headers,
            }

            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    self._url,
                    json=payload,
                    headers=headers,
                )
                response.raise_for_status()
                return True

        except ImportError:
            logger.warning("httpx not installed, webhook alerts disabled")
            return False
        except (
            httpx.RequestError,
            httpx.HTTPStatusError,
        ) as e:
            logger.error(
                "Failed to send async webhook alert: %s",
                e,
            )
            return False
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error(
                "Failed to send async webhook alert: %s",
                e,
            )
            return False


class SlackAlertChannel(WebhookAlertChannel):
    """Specialized webhook channel for Slack."""

    def __init__(
        self,
        webhook_url: str,
        *,
        channel: str | None = None,
        username: str = "AgentGate Security",
        icon_emoji: str = ":shield:",
        min_priority: AlertPriority = AlertPriority.MEDIUM,
    ):
        """
        Initialize Slack channel.

        Args:
            webhook_url: Slack webhook URL.
            channel: Optional channel override.
            username: Bot username.
            icon_emoji: Bot icon.
            min_priority: Minimum priority to send.
        """
        self._channel = channel
        self._username = username
        self._icon_emoji = icon_emoji

        super().__init__(
            url=webhook_url,
            min_priority=min_priority,
            transform=self._to_slack_format,
        )
        self._name = "slack"

    def _get_color(self, priority: AlertPriority) -> str:
        """Get Slack attachment color for priority."""
        colors = {
            AlertPriority.LOW: "#36a64f",
            AlertPriority.MEDIUM: "#ffc107",
            AlertPriority.HIGH: "#ff9800",
            AlertPriority.CRITICAL: "#dc3545",
        }
        return colors[priority]

    def _to_slack_format(self, alert: SecurityAlert) -> dict[str, Any]:
        """Transform alert to Slack message format."""
        fields = [
            {
                "title": "Priority",
                "value": alert.priority.value.upper(),
                "short": True,
            },
            {
                "title": "Category",
                "value": alert.category,
                "short": True,
            },
            {
                "title": "Source",
                "value": alert.source,
                "short": True,
            },
        ]

        if alert.ip_address:
            fields.append(
                {
                    "title": "IP Address",
                    "value": alert.ip_address,
                    "short": True,
                }
            )

        if alert.user_email:
            fields.append(
                {
                    "title": "User",
                    "value": alert.user_email,
                    "short": True,
                }
            )

        payload: dict[str, Any] = {
            "username": self._username,
            "icon_emoji": self._icon_emoji,
            "attachments": [
                {
                    "color": self._get_color(alert.priority),
                    "title": alert.title,
                    "text": alert.description,
                    "fields": fields,
                    "footer": (f"Alert ID: {alert.alert_id}"),
                    "ts": int(alert.timestamp),
                }
            ],
        }

        if self._channel:
            payload["channel"] = self._channel

        return payload


__all__ = [
    "LogAlertChannel",
    "WebhookAlertChannel",
    "SlackAlertChannel",
]
