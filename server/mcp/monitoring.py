"""MCP monitoring helpers for alerting and observability hooks."""

from __future__ import annotations

from importlib import import_module
import logging
from typing import Any, Literal

from server.policy_governance.kernel.alerts import SecurityAlertManager

logger = logging.getLogger(__name__)


class _MonitoringState:
    """Module-level singleton state for the alert manager."""

    alert_manager: SecurityAlertManager | Literal[False] | None = None

    @classmethod
    def get_cached(cls) -> SecurityAlertManager | Literal[False] | None:
        """Return the cached alert manager state."""
        return cls.alert_manager

    @classmethod
    def set_cached(cls, manager: SecurityAlertManager | Literal[False]) -> None:
        """Store the alert manager state."""
        cls.alert_manager = manager


def _get_alert_manager() -> SecurityAlertManager | Literal[False]:
    """Lazy-load runtime alert manager if alerting dependencies are available."""
    cached = _MonitoringState.get_cached()
    if cached is not None:
        return cached

    try:
        factory_module = import_module("server.policy_governance.kernel.alerting_factory")
        build_alert_manager_from_environment = getattr(
            factory_module,
            "build_alert_manager_from_environment",
        )
        _MonitoringState.set_cached(build_alert_manager_from_environment())
    except (AttributeError, ImportError, OSError, RuntimeError, ValueError) as exc:
        logger.warning("MCP monitoring alert manager unavailable: %s", exc)
        _MonitoringState.set_cached(False)

    cached = _MonitoringState.get_cached()
    if cached is None:
        return False
    return cached


async def emit_failure_alert(
    *,
    event_type: str,
    title: str,
    description: str,
    severity: str,
    correlation_id: str | None,
    details: dict[str, Any] | None = None,
) -> None:
    """Emit a best-effort alert for MCP failure/security events."""
    manager = _get_alert_manager()
    if not manager:
        return

    try:
        alert_module = import_module("server.policy_governance.kernel.alerts")
        alert_priority = getattr(alert_module, "AlertPriority")

        priority_map = {
            "low": alert_priority.LOW,
            "medium": alert_priority.MEDIUM,
            "high": alert_priority.HIGH,
            "critical": alert_priority.CRITICAL,
        }
        priority = priority_map.get(severity.lower(), alert_priority.MEDIUM)

        payload = dict(details or {})
        if correlation_id:
            payload["correlation_id"] = correlation_id

        alert = manager.create_alert(
            title=title,
            description=description,
            priority=priority,
            source="mcp",
            category=event_type,
            details=payload,
        )
        await manager.send_alert_async(alert)
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as exc:
        logger.warning("Failed to emit MCP failure alert (%s): %s", event_type, exc)
