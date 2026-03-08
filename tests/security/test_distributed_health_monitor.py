"""Tests for distributed health monitor runtime behavior."""

from __future__ import annotations

from dataclasses import dataclass

import httpx
import pytest

from server.policy_governance.kernel.distributed_health_monitor import (
    DistributedHealthMonitor,
    HealthMonitorTarget,
    resolve_health_monitor_runtime_config,
)


@dataclass
class _CapturedAlert:
    title: str
    description: str
    category: str
    source: str
    details: dict


class _StubAlertManager:
    """Alert manager stub that records created and sent alerts."""

    def __init__(self) -> None:
        self.created: list[_CapturedAlert] = []
        self.sent: list[dict] = []

    def create_alert(
        self,
        *,
        title: str,
        description: str,
        priority,
        category: str,
        source: str,
        details: dict,
        tags: list[str] | None = None,
    ) -> dict:
        """Create an alert payload and record the captured fields."""
        _ = priority, tags
        payload = {
            "title": title,
            "description": description,
            "category": category,
            "source": source,
            "details": details,
        }
        self.created.append(
            _CapturedAlert(
                title=title,
                description=description,
                category=category,
                source=source,
                details=details,
            )
        )
        return payload

    async def send_alert_async(self, alert: dict) -> bool:
        """Record the alert payload and report success."""
        self.sent.append(alert)
        return True


@pytest.mark.asyncio
async def test_monitor_sends_failure_and_recovery_alerts() -> None:
    """Monitor should alert after threshold failures and again on recovery."""
    status_sequence = [503, 503, 200]

    async def _handler(_request: httpx.Request) -> httpx.Response:
        if not status_sequence:
            return httpx.Response(200, text="ok")
        status_code = status_sequence.pop(0)
        return httpx.Response(status_code, text="ok" if status_code == 200 else "down")

    alert_manager = _StubAlertManager()
    monitor = DistributedHealthMonitor(
        targets=[HealthMonitorTarget(name="api", url="http://health.test")],
        alert_manager=alert_manager,  # type: ignore[arg-type]
        interval_seconds=30.0,
        timeout_seconds=5.0,
        failure_threshold=2,
    )
    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(_handler))
    vars(monitor)["_http_client"] = mock_client

    await monitor.run_once()
    snapshot = monitor.snapshot()
    assert snapshot["targets"]["api"]["consecutive_failures"] == 1
    assert len(alert_manager.sent) == 0

    await monitor.run_once()
    snapshot = monitor.snapshot()
    assert snapshot["targets"]["api"]["consecutive_failures"] == 2
    assert snapshot["targets"]["api"]["alert_open"] is True
    assert len(alert_manager.sent) == 1
    assert alert_manager.sent[0]["title"].startswith("Health Monitor Failure")

    await monitor.run_once()
    snapshot = monitor.snapshot()
    assert snapshot["targets"]["api"]["is_healthy"] is True
    assert snapshot["targets"]["api"]["consecutive_failures"] == 0
    assert snapshot["targets"]["api"]["alert_open"] is False
    assert len(alert_manager.sent) == 2
    assert alert_manager.sent[1]["title"].startswith("Health Monitor Recovery")

    await vars(monitor)["_http_client"].aclose()


def test_resolve_health_monitor_runtime_config_json_targets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Runtime config should parse structured target JSON and thresholds."""
    monkeypatch.setenv("AGENTGATE_DISTRIBUTED_HEALTH_MONITOR_ENABLED", "true")
    monkeypatch.setenv(
        "AGENTGATE_DISTRIBUTED_HEALTH_MONITOR_TARGETS_JSON",
        '[{"name":"api","url":"http://localhost:8000/api/health","expected_status":200}]',
    )
    monkeypatch.setenv("AGENTGATE_DISTRIBUTED_HEALTH_MONITOR_INTERVAL_SECONDS", "15")
    monkeypatch.setenv("AGENTGATE_DISTRIBUTED_HEALTH_MONITOR_FAILURE_THRESHOLD", "3")

    config = resolve_health_monitor_runtime_config()
    assert config.enabled is True
    assert len(config.targets) == 1
    assert config.targets[0].name == "api"
    assert config.targets[0].expected_status == 200
    assert config.interval_seconds == 15.0
    assert config.failure_threshold == 3
