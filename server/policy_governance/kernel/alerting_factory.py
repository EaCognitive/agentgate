"""Runtime construction helpers for security alert delivery."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass

from .alerts import (
    AlertChannel,
    AlertPriority,
    LogAlertChannel,
    RateLimitConfig,
    SecurityAlertManager,
    SlackAlertChannel,
    WebhookAlertChannel,
)

logger = logging.getLogger(__name__)


def _parse_priority(
    raw_value: str | None,
    *,
    env_key: str,
    default_value: AlertPriority,
) -> AlertPriority:
    """Parse an alert priority enum from environment."""
    if raw_value is None:
        return default_value

    normalized = raw_value.strip().lower()
    if not normalized:
        return default_value

    try:
        return AlertPriority(normalized)
    except ValueError:
        logger.warning(
            "Invalid %s value '%s'. Falling back to %s.",
            env_key,
            raw_value,
            default_value.value,
        )
        return default_value


def _parse_float(
    raw_value: str | None,
    *,
    env_key: str,
    default_value: float,
    minimum: float,
) -> float:
    """Parse a bounded float environment value."""
    if raw_value is None:
        return default_value

    normalized = raw_value.strip()
    if not normalized:
        return default_value

    try:
        parsed = float(normalized)
    except ValueError:
        logger.warning(
            "Invalid %s value '%s'. Falling back to %.2f.",
            env_key,
            raw_value,
            default_value,
        )
        return default_value

    if parsed < minimum:
        logger.warning(
            "Invalid %s value '%s'. Must be >= %.2f. Falling back to %.2f.",
            env_key,
            raw_value,
            minimum,
            default_value,
        )
        return default_value
    return parsed


def _parse_int(
    raw_value: str | None,
    *,
    env_key: str,
    default_value: int,
    minimum: int,
) -> int:
    """Parse a bounded integer environment value."""
    if raw_value is None:
        return default_value

    normalized = raw_value.strip()
    if not normalized:
        return default_value

    try:
        parsed = int(normalized)
    except ValueError:
        logger.warning(
            "Invalid %s value '%s'. Falling back to %d.",
            env_key,
            raw_value,
            default_value,
        )
        return default_value

    if parsed < minimum:
        logger.warning(
            "Invalid %s value '%s'. Must be >= %d. Falling back to %d.",
            env_key,
            raw_value,
            minimum,
            default_value,
        )
        return default_value
    return parsed


def _parse_headers_json(raw_headers: str | None) -> dict[str, str]:
    """Parse optional webhook headers from JSON environment value."""
    if raw_headers is None:
        return {}
    payload = raw_headers.strip()
    if not payload:
        return {}

    try:
        loaded = json.loads(payload)
    except json.JSONDecodeError:
        logger.warning(
            "SECURITY_ALERT_WEBHOOK_HEADERS_JSON is not valid JSON. Ignoring custom headers."
        )
        return {}

    if not isinstance(loaded, dict):
        logger.warning(
            "SECURITY_ALERT_WEBHOOK_HEADERS_JSON must be a JSON object. Ignoring custom headers."
        )
        return {}

    headers: dict[str, str] = {}
    for key, value in loaded.items():
        if not isinstance(key, str) or not isinstance(value, str):
            logger.warning(
                "Ignoring non-string webhook header entry key=%r value=%r.",
                key,
                value,
            )
            continue
        headers[key] = value
    return headers


@dataclass(frozen=True)
class AlertRuntimeConfig:
    """Resolved runtime configuration for alert channels and rate limiting."""

    log_min_priority: AlertPriority
    webhook_url: str | None
    webhook_min_priority: AlertPriority
    webhook_headers: dict[str, str]
    webhook_timeout_seconds: float
    slack_webhook_url: str | None
    slack_channel: str | None
    slack_min_priority: AlertPriority
    dedup_window_seconds: float
    rate_limit_config: RateLimitConfig


def resolve_alert_runtime_config() -> AlertRuntimeConfig:
    """Resolve security alert runtime config from environment variables."""
    log_min_priority = _parse_priority(
        os.getenv("SECURITY_ALERT_LOG_MIN_PRIORITY"),
        env_key="SECURITY_ALERT_LOG_MIN_PRIORITY",
        default_value=AlertPriority.LOW,
    )
    webhook_min_priority = _parse_priority(
        os.getenv("SECURITY_ALERT_WEBHOOK_MIN_PRIORITY"),
        env_key="SECURITY_ALERT_WEBHOOK_MIN_PRIORITY",
        default_value=AlertPriority.HIGH,
    )
    slack_min_priority = _parse_priority(
        os.getenv("SECURITY_ALERT_SLACK_MIN_PRIORITY"),
        env_key="SECURITY_ALERT_SLACK_MIN_PRIORITY",
        default_value=AlertPriority.HIGH,
    )
    webhook_timeout_seconds = _parse_float(
        os.getenv("SECURITY_ALERT_WEBHOOK_TIMEOUT_SECONDS"),
        env_key="SECURITY_ALERT_WEBHOOK_TIMEOUT_SECONDS",
        default_value=10.0,
        minimum=1.0,
    )

    dedup_window_seconds = _parse_float(
        os.getenv("SECURITY_ALERT_DEDUP_WINDOW_SECONDS"),
        env_key="SECURITY_ALERT_DEDUP_WINDOW_SECONDS",
        default_value=300.0,
        minimum=0.0,
    )
    rate_limit = RateLimitConfig(
        window_seconds=_parse_float(
            os.getenv("SECURITY_ALERT_WINDOW_SECONDS"),
            env_key="SECURITY_ALERT_WINDOW_SECONDS",
            default_value=60.0,
            minimum=1.0,
        ),
        max_alerts_per_window=_parse_int(
            os.getenv("SECURITY_ALERT_MAX_PER_WINDOW"),
            env_key="SECURITY_ALERT_MAX_PER_WINDOW",
            default_value=10,
            minimum=1,
        ),
        cooldown_seconds=_parse_float(
            os.getenv("SECURITY_ALERT_COOLDOWN_SECONDS"),
            env_key="SECURITY_ALERT_COOLDOWN_SECONDS",
            default_value=300.0,
            minimum=1.0,
        ),
        max_alerts_during_cooldown=_parse_int(
            os.getenv("SECURITY_ALERT_MAX_DURING_COOLDOWN"),
            env_key="SECURITY_ALERT_MAX_DURING_COOLDOWN",
            default_value=1,
            minimum=1,
        ),
    )

    webhook_url = os.getenv("SECURITY_ALERT_WEBHOOK_URL", "").strip() or None
    webhook_headers = _parse_headers_json(
        os.getenv("SECURITY_ALERT_WEBHOOK_HEADERS_JSON"),
    )
    slack_webhook_url = os.getenv("SECURITY_ALERT_SLACK_WEBHOOK_URL", "").strip() or None
    slack_channel = os.getenv("SECURITY_ALERT_SLACK_CHANNEL", "").strip() or None

    return AlertRuntimeConfig(
        log_min_priority=log_min_priority,
        webhook_url=webhook_url,
        webhook_min_priority=webhook_min_priority,
        webhook_headers=webhook_headers,
        webhook_timeout_seconds=webhook_timeout_seconds,
        slack_webhook_url=slack_webhook_url,
        slack_channel=slack_channel,
        slack_min_priority=slack_min_priority,
        dedup_window_seconds=dedup_window_seconds,
        rate_limit_config=rate_limit,
    )


def build_alert_manager_from_environment() -> SecurityAlertManager:
    """Build a runtime-configured alert manager for threat/health notifications."""
    config = resolve_alert_runtime_config()
    channels: list[AlertChannel] = [LogAlertChannel(min_priority=config.log_min_priority)]

    if config.webhook_url:
        channels.append(
            WebhookAlertChannel(
                url=config.webhook_url,
                headers=config.webhook_headers,
                timeout=config.webhook_timeout_seconds,
                min_priority=config.webhook_min_priority,
            )
        )

    if config.slack_webhook_url:
        channels.append(
            SlackAlertChannel(
                webhook_url=config.slack_webhook_url,
                channel=config.slack_channel,
                min_priority=config.slack_min_priority,
            )
        )

    return SecurityAlertManager(
        channels=channels,
        rate_limit=config.rate_limit_config,
        dedup_window_seconds=config.dedup_window_seconds,
    )


__all__ = [
    "AlertRuntimeConfig",
    "resolve_alert_runtime_config",
    "build_alert_manager_from_environment",
]
