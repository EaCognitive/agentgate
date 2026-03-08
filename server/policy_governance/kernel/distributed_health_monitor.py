"""Distributed service health monitoring with security alert integration."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx

from server.metrics import (
    record_health_monitor_probe,
    set_health_monitor_target_status,
)
from .alerts import AlertPriority, SecurityAlertManager
from .alerting_factory import build_alert_manager_from_environment

logger = logging.getLogger(__name__)

_TRUE_VALUES = {"1", "true", "yes", "on"}


class _HealthMonitorState:
    """Module-level singleton state for the active health monitor."""

    active_monitor: "DistributedHealthMonitor | None" = None

    @classmethod
    def get_active_monitor(cls) -> "DistributedHealthMonitor | None":
        """Return the currently active monitor instance."""
        return cls.active_monitor

    @classmethod
    def set_active_monitor(cls, monitor: "DistributedHealthMonitor | None") -> None:
        """Update the currently active monitor instance."""
        cls.active_monitor = monitor


def _is_truthy(raw_value: str | None) -> bool:
    if raw_value is None:
        return False
    return raw_value.strip().lower() in _TRUE_VALUES


def _parse_float(
    raw_value: str | None,
    *,
    env_key: str,
    default_value: float,
    minimum: float,
) -> float:
    """Parse a bounded float value from environment."""
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
    """Parse a bounded integer value from environment."""
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


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class HealthMonitorTarget:
    """Health target configuration."""

    name: str
    url: str
    expected_status: int = 200
    expected_substring: str | None = None


@dataclass
class TargetHealthState:
    """Mutable health state for a monitored target."""

    is_healthy: bool = True
    consecutive_failures: int = 0
    alert_open: bool = False
    last_checked_at: str | None = None
    last_success_at: str | None = None
    last_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert target state to serializable payload."""
        return {
            "is_healthy": self.is_healthy,
            "consecutive_failures": self.consecutive_failures,
            "alert_open": self.alert_open,
            "last_checked_at": self.last_checked_at,
            "last_success_at": self.last_success_at,
            "last_error": self.last_error,
        }


@dataclass(frozen=True)
class HealthMonitorRuntimeConfig:
    """Resolved runtime configuration for distributed health monitoring."""

    enabled: bool
    targets: list[HealthMonitorTarget]
    interval_seconds: float
    timeout_seconds: float
    failure_threshold: int


def _parse_targets_json(raw_targets: str) -> list[HealthMonitorTarget]:
    """Parse structured health monitor targets from JSON."""
    parsed = json.loads(raw_targets)
    if not isinstance(parsed, list):
        raise ValueError("AGENTGATE_DISTRIBUTED_HEALTH_MONITOR_TARGETS_JSON must be a JSON list")

    targets: list[HealthMonitorTarget] = []
    for index, item in enumerate(parsed):
        if not isinstance(item, dict):
            raise ValueError(
                "AGENTGATE_DISTRIBUTED_HEALTH_MONITOR_TARGETS_JSON entries must be objects"
            )
        name = str(item.get("name", "")).strip()
        url = str(item.get("url", "")).strip()
        if not name or not url:
            raise ValueError(
                f"AGENTGATE_DISTRIBUTED_HEALTH_MONITOR_TARGETS_JSON entry {index} "
                "requires non-empty name and url fields"
            )
        expected_status_raw = item.get("expected_status", 200)
        try:
            expected_status = int(expected_status_raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"Invalid expected_status for target '{name}': {expected_status_raw}"
            ) from exc

        expected_substring_raw = item.get("expected_substring")
        expected_substring = (
            str(expected_substring_raw).strip() if expected_substring_raw is not None else None
        )
        targets.append(
            HealthMonitorTarget(
                name=name,
                url=url,
                expected_status=expected_status,
                expected_substring=expected_substring or None,
            )
        )

    return targets


def _parse_targets(raw_targets: str | None) -> list[HealthMonitorTarget]:
    """Parse simple monitor target configuration."""
    if raw_targets is None:
        return []
    payload = raw_targets.strip()
    if not payload:
        return []

    targets: list[HealthMonitorTarget] = []
    for idx, token in enumerate(payload.split(","), start=1):
        candidate = token.strip()
        if not candidate:
            continue

        name = ""
        url = ""
        expected_substring: str | None = None
        if "|" in candidate:
            parts = [part.strip() for part in candidate.split("|")]
            if len(parts) < 2:
                continue
            name = parts[0]
            url = parts[1]
            expected_substring = parts[2] if len(parts) >= 3 and parts[2] else None
        elif "=" in candidate:
            name, url = [part.strip() for part in candidate.split("=", maxsplit=1)]
        else:
            name = f"target_{idx}"
            url = candidate

        if not name or not url:
            continue
        targets.append(
            HealthMonitorTarget(
                name=name,
                url=url,
                expected_status=200,
                expected_substring=expected_substring,
            )
        )
    return targets


def resolve_health_monitor_runtime_config() -> HealthMonitorRuntimeConfig:
    """Resolve distributed health monitor runtime configuration."""
    enabled = _is_truthy(os.getenv("AGENTGATE_DISTRIBUTED_HEALTH_MONITOR_ENABLED"))
    targets: list[HealthMonitorTarget] = []

    json_targets_raw = os.getenv("AGENTGATE_DISTRIBUTED_HEALTH_MONITOR_TARGETS_JSON")
    if json_targets_raw and json_targets_raw.strip():
        try:
            targets = _parse_targets_json(json_targets_raw.strip())
        except ValueError as exc:
            logger.warning("Invalid JSON health monitor targets configuration: %s", exc)
            targets = []
    else:
        targets = _parse_targets(os.getenv("AGENTGATE_DISTRIBUTED_HEALTH_MONITOR_TARGETS"))

    include_dashboard = _is_truthy(os.getenv("AGENTGATE_HEALTH_MONITOR_INCLUDE_DASHBOARD"))
    dashboard_url = os.getenv("AGENTGATE_DASHBOARD_HEALTH_URL", "").strip()
    if include_dashboard and dashboard_url:
        if all(t.name != "dashboard" for t in targets):
            targets.append(HealthMonitorTarget(name="dashboard", url=dashboard_url))

    interval_seconds = _parse_float(
        os.getenv("AGENTGATE_DISTRIBUTED_HEALTH_MONITOR_INTERVAL_SECONDS"),
        env_key="AGENTGATE_DISTRIBUTED_HEALTH_MONITOR_INTERVAL_SECONDS",
        default_value=30.0,
        minimum=5.0,
    )
    timeout_seconds = _parse_float(
        os.getenv("AGENTGATE_DISTRIBUTED_HEALTH_MONITOR_TIMEOUT_SECONDS"),
        env_key="AGENTGATE_DISTRIBUTED_HEALTH_MONITOR_TIMEOUT_SECONDS",
        default_value=5.0,
        minimum=1.0,
    )
    failure_threshold = _parse_int(
        os.getenv("AGENTGATE_DISTRIBUTED_HEALTH_MONITOR_FAILURE_THRESHOLD"),
        env_key="AGENTGATE_DISTRIBUTED_HEALTH_MONITOR_FAILURE_THRESHOLD",
        default_value=2,
        minimum=1,
    )

    return HealthMonitorRuntimeConfig(
        enabled=enabled,
        targets=targets,
        interval_seconds=interval_seconds,
        timeout_seconds=timeout_seconds,
        failure_threshold=failure_threshold,
    )


class DistributedHealthMonitor:
    """Periodic distributed endpoint health monitor with alerting."""

    def __init__(
        self,
        *,
        targets: list[HealthMonitorTarget],
        alert_manager: SecurityAlertManager,
        interval_seconds: float,
        timeout_seconds: float,
        failure_threshold: int,
    ) -> None:
        self._targets = targets
        self._alert_manager = alert_manager
        self._interval_seconds = interval_seconds
        self._timeout_seconds = timeout_seconds
        self._failure_threshold = failure_threshold
        self._states: dict[str, TargetHealthState] = {
            target.name: TargetHealthState() for target in targets
        }
        self._http_client: httpx.AsyncClient | None = None
        self._task: asyncio.Task[None] | None = None
        self._stop_event = asyncio.Event()

    @property
    def running(self) -> bool:
        """Return whether monitor loop is currently active."""
        return self._task is not None and not self._task.done()

    async def start(self) -> None:
        """Start background monitor loop."""
        if self.running:
            return

        self._http_client = httpx.AsyncClient(timeout=self._timeout_seconds)
        self._stop_event.clear()
        self._task = asyncio.create_task(
            self._run_loop(),
            name="agentgate-distributed-health-monitor",
        )

    async def stop(self) -> None:
        """Stop monitor loop and release resources."""
        self._stop_event.set()
        if self._task is not None:
            try:
                await self._task
            finally:
                self._task = None
        if self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None

    async def _run_loop(self) -> None:
        """Run monitor probes until stop signal."""
        while not self._stop_event.is_set():
            await self.run_once()
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=self._interval_seconds,
                )
            except TimeoutError:
                continue

    async def run_once(self) -> None:
        """Execute a single probe pass over all targets."""
        for target in self._targets:
            await self._probe_target(target)

    async def _probe_target(self, target: HealthMonitorTarget) -> None:
        """Probe a target URL and update health state."""
        if self._http_client is None:
            raise RuntimeError("Health monitor HTTP client is not initialized")

        state = self._states[target.name]
        state.last_checked_at = _utc_now_iso()
        set_health_monitor_target_status(target.name, is_healthy=state.is_healthy)

        failure_reason: str | None = None
        response_status: int | None = None
        try:
            response = await self._http_client.get(target.url)
            response_status = response.status_code
            if response.status_code != target.expected_status:
                failure_reason = (
                    f"unexpected_status:{response.status_code}:expected={target.expected_status}"
                )
            elif target.expected_substring and target.expected_substring not in response.text:
                failure_reason = "missing_expected_substring"
        except httpx.HTTPError as exc:
            failure_reason = f"http_error:{exc.__class__.__name__}:{exc}"

        if failure_reason is None:
            record_health_monitor_probe(target.name, result="healthy")
            was_alert_open = state.alert_open
            state.is_healthy = True
            state.consecutive_failures = 0
            state.last_error = None
            state.last_success_at = _utc_now_iso()
            state.alert_open = False
            set_health_monitor_target_status(target.name, is_healthy=True)
            if was_alert_open:
                await self._send_recovery_alert(target=target)
            return

        state.is_healthy = False
        state.consecutive_failures += 1
        state.last_error = failure_reason
        record_health_monitor_probe(target.name, result="failed")
        set_health_monitor_target_status(target.name, is_healthy=False)
        logger.warning(
            "Health probe failed target=%s url=%s reason=%s status=%s consecutive_failures=%d",
            target.name,
            target.url,
            failure_reason,
            response_status,
            state.consecutive_failures,
        )

        if state.consecutive_failures >= self._failure_threshold and not state.alert_open:
            state.alert_open = True
            await self._send_failure_alert(target=target, reason=failure_reason)

    async def _send_failure_alert(self, *, target: HealthMonitorTarget, reason: str) -> None:
        """Send an alert for sustained target health failures."""
        alert = self._alert_manager.create_alert(
            title=f"Health Monitor Failure: {target.name}",
            description=(
                f"Target '{target.name}' failed health checks "
                f"{self._failure_threshold} consecutive times"
            ),
            priority=AlertPriority.HIGH,
            category="service_health",
            source="distributed_health_monitor",
            details={
                "target_name": target.name,
                "target_url": target.url,
                "failure_threshold": self._failure_threshold,
                "reason": reason,
                "state": self._states[target.name].to_dict(),
            },
            tags=["health_monitor", "service_availability"],
        )
        await self._alert_manager.send_alert_async(alert)

    async def _send_recovery_alert(self, *, target: HealthMonitorTarget) -> None:
        """Send an alert when a previously failing target recovers."""
        alert = self._alert_manager.create_alert(
            title=f"Health Monitor Recovery: {target.name}",
            description=f"Target '{target.name}' recovered after health check failures",
            priority=AlertPriority.MEDIUM,
            category="service_health",
            source="distributed_health_monitor",
            details={
                "target_name": target.name,
                "target_url": target.url,
                "state": self._states[target.name].to_dict(),
            },
            tags=["health_monitor", "service_recovery"],
        )
        await self._alert_manager.send_alert_async(alert)

    def snapshot(self) -> dict[str, Any]:
        """Return monitor runtime snapshot for health endpoints and diagnostics."""
        targets_payload = {
            target.name: self._states[target.name].to_dict() for target in self._targets
        }
        all_healthy = all(state.is_healthy for state in self._states.values())
        overall_status = "healthy" if all_healthy else "degraded"
        return {
            "enabled": True,
            "running": self.running,
            "overall_status": overall_status,
            "interval_seconds": self._interval_seconds,
            "timeout_seconds": self._timeout_seconds,
            "failure_threshold": self._failure_threshold,
            "target_count": len(self._targets),
            "targets": targets_payload,
        }


def _set_active_monitor(
    monitor: DistributedHealthMonitor | None,
) -> None:
    """Update the module-level active health monitor reference."""
    _HealthMonitorState.active_monitor = monitor


async def start_distributed_health_monitor_from_environment() -> DistributedHealthMonitor | None:
    """Start distributed health monitor when runtime config enables it."""
    monitor = _HealthMonitorState.active_monitor
    if monitor is not None and monitor.running:
        return monitor

    runtime_config = resolve_health_monitor_runtime_config()
    if not runtime_config.enabled:
        return None
    if not runtime_config.targets:
        logger.warning(
            "Distributed health monitor enabled but no targets configured. "
            "Set AGENTGATE_DISTRIBUTED_HEALTH_MONITOR_TARGETS or "
            "AGENTGATE_DISTRIBUTED_HEALTH_MONITOR_TARGETS_JSON."
        )
        return None

    monitor = DistributedHealthMonitor(
        targets=runtime_config.targets,
        alert_manager=build_alert_manager_from_environment(),
        interval_seconds=runtime_config.interval_seconds,
        timeout_seconds=runtime_config.timeout_seconds,
        failure_threshold=runtime_config.failure_threshold,
    )
    await monitor.start()
    _set_active_monitor(monitor)
    logger.info(
        "Distributed health monitor started targets=%s interval=%.1fs threshold=%d",
        [target.name for target in runtime_config.targets],
        runtime_config.interval_seconds,
        runtime_config.failure_threshold,
    )
    return monitor


async def stop_distributed_health_monitor() -> None:
    """Stop active distributed health monitor if running."""
    monitor = _HealthMonitorState.active_monitor
    _set_active_monitor(None)
    if monitor is None:
        return
    await monitor.stop()
    logger.info("Distributed health monitor stopped")


def get_distributed_health_monitor_snapshot() -> dict[str, Any]:
    """Return current monitor snapshot payload."""
    if _HealthMonitorState.active_monitor is None:
        runtime_config = resolve_health_monitor_runtime_config()
        return {
            "enabled": runtime_config.enabled,
            "running": False,
            "overall_status": "disabled" if not runtime_config.enabled else "not_configured",
            "interval_seconds": runtime_config.interval_seconds,
            "timeout_seconds": runtime_config.timeout_seconds,
            "failure_threshold": runtime_config.failure_threshold,
            "target_count": len(runtime_config.targets),
            "targets": {},
        }
    return _HealthMonitorState.active_monitor.snapshot()


__all__ = [
    "HealthMonitorTarget",
    "HealthMonitorRuntimeConfig",
    "DistributedHealthMonitor",
    "resolve_health_monitor_runtime_config",
    "start_distributed_health_monitor_from_environment",
    "stop_distributed_health_monitor",
    "get_distributed_health_monitor_snapshot",
]
