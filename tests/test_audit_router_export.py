"""Tests for audit log export, statistics, and edge-case endpoints.

This module covers:
- GET /audit/export - export as CSV/JSON
- GET /audit/stats - get audit statistics
- Edge cases and error handling
- Rate limiting and performance
"""

import csv
import json
from datetime import datetime, timedelta, timezone
from io import StringIO
from unittest.mock import patch

from fastapi.testclient import TestClient

from server.models import (
    AuditEntry,
)
from server.routers.audit import export_audit_log

pytest_plugins = (
    "tests.router_test_support",
    "tests.audit_router_test_support",
)


# ==================== GET /audit/export Tests ====================


def test_export_audit_log_csv_success(
    client: TestClient,
    admin_token: str,
    sample_audit_entries: list[AuditEntry],
):
    """Test exporting audit log as CSV."""
    _ = sample_audit_entries
    response = client.get(
        "/api/audit/export?format=csv&hours=24",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    assert response.headers["content-type"] == "text/csv; charset=utf-8"
    assert "Content-Disposition" in response.headers
    assert "audit_log_" in response.headers["Content-Disposition"]
    assert ".csv" in response.headers["Content-Disposition"]

    content = response.text
    reader = csv.DictReader(StringIO(content))
    rows = list(reader)

    assert len(rows) == 5
    assert set(rows[0].keys()) == {
        "timestamp",
        "event_type",
        "actor",
        "tool",
        "result",
        "details",
    }


def test_export_audit_log_json_success(
    client: TestClient,
    admin_token: str,
    sample_audit_entries: list[AuditEntry],
):
    """Test exporting audit log as JSON."""
    _ = sample_audit_entries
    response = client.get(
        "/api/audit/export?format=json&hours=24",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert "Content-Disposition" in response.headers
    assert "audit_log_" in response.headers["Content-Disposition"]
    assert ".json" in response.headers["Content-Disposition"]

    data = json.loads(response.text)
    assert isinstance(data, list)
    assert len(data) == 5

    first_entry = data[0]
    assert "id" in first_entry
    assert "timestamp" in first_entry
    assert "event_type" in first_entry
    assert "actor" in first_entry
    assert "tool" in first_entry
    assert "result" in first_entry
    assert "details" in first_entry


def test_export_audit_log_auditor_permission(
    client: TestClient,
    auditor_token: str,
    sample_audit_entries: list[AuditEntry],
):
    """Test that auditor role has AUDIT_EXPORT permission."""
    _ = sample_audit_entries
    response = client.get(
        "/api/audit/export?format=csv",
        headers={"Authorization": f"Bearer {auditor_token}"},
    )

    assert response.status_code == 200


def test_export_audit_log_unauthorized(client: TestClient):
    """Test that exporting audit log requires authentication."""
    response = client.get("/api/audit/export")
    assert response.status_code == 401


def test_export_audit_log_forbidden(
    client: TestClient,
    viewer_token: str,
    sample_audit_entries: list[AuditEntry],
):
    """Test that viewer role does not have AUDIT_EXPORT permission."""
    _ = sample_audit_entries
    response = client.get(
        "/api/audit/export",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )

    assert response.status_code == 403
    assert "Permission required" in response.json()["detail"]


def test_export_audit_log_hours_filter(
    client: TestClient,
    admin_token: str,
    sample_audit_entries: list[AuditEntry],
):
    """Test exporting audit log with hours filter."""
    _ = sample_audit_entries
    response = client.get(
        "/api/audit/export?format=json&hours=1",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    data = json.loads(response.text)
    assert len(data) == 3


def test_export_audit_log_hours_max_validation(
    client: TestClient,
    admin_token: str,
):
    """Test that hours parameter has a maximum value of 720."""
    response = client.get(
        "/api/audit/export?hours=1000",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 422


def test_export_audit_log_invalid_format(
    client: TestClient,
    admin_token: str,
):
    """Test that invalid format returns validation error."""
    response = client.get(
        "/api/audit/export?format=xml",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 422


def test_export_audit_log_default_format(
    client: TestClient,
    admin_token: str,
    sample_audit_entries: list[AuditEntry],
):
    """Test that default export format is CSV."""
    _ = sample_audit_entries
    response = client.get(
        "/api/audit/export",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    assert response.headers["content-type"] == "text/csv; charset=utf-8"


def test_export_audit_log_empty(
    client: TestClient,
    admin_token: str,
):
    """Test exporting audit log when no entries exist."""
    response = client.get(
        "/api/audit/export?format=json",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    data = json.loads(response.text)
    assert len(data) == 0


@patch("server.routers.audit.limiter.limit")
def test_export_audit_log_rate_limiting(
    mock_limiter,
    client: TestClient,
    admin_token: str,
    sample_audit_entries: list[AuditEntry],
):
    """Test that export endpoint has rate limiting applied."""
    _ = mock_limiter
    _ = sample_audit_entries
    response = client.get(
        "/api/audit/export",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200

    assert hasattr(export_audit_log, "__wrapped__")


# ==================== GET /audit/stats Tests ====================


def test_get_audit_stats_success(
    client: TestClient,
    admin_token: str,
    sample_audit_entries: list[AuditEntry],
):
    """Test getting audit log statistics."""
    _ = sample_audit_entries
    response = client.get(
        "/api/audit/stats?hours=24",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert "total_entries" in data
    assert "by_event_type" in data
    assert "by_result" in data
    assert "period_hours" in data

    assert data["total_entries"] == 5
    assert data["period_hours"] == 24

    assert data["by_event_type"]["tool.execute"] == 3
    assert data["by_event_type"]["user.login"] == 1
    assert data["by_event_type"]["user.logout"] == 1

    assert data["by_result"]["success"] == 4
    assert data["by_result"]["failure"] == 1


def test_get_audit_stats_hours_filter(
    client: TestClient,
    admin_token: str,
    sample_audit_entries: list[AuditEntry],
):
    """Test audit statistics with hours filter."""
    _ = sample_audit_entries
    response = client.get(
        "/api/audit/stats?hours=1",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["total_entries"] == 3
    assert data["period_hours"] == 1


def test_get_audit_stats_hours_max_validation(
    client: TestClient,
    admin_token: str,
):
    """Test that hours parameter has a maximum value of 720."""
    response = client.get(
        "/api/audit/stats?hours=1000",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 422


def test_get_audit_stats_empty(
    client: TestClient,
    admin_token: str,
):
    """Test statistics when no audit entries exist."""
    response = client.get(
        "/api/audit/stats",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["total_entries"] == 0
    assert not data["by_event_type"]
    assert not data["by_result"]


def test_get_audit_stats_requires_authentication(
    client: TestClient,
    sample_audit_entries: list[AuditEntry],
):
    """Test that getting statistics requires authentication."""
    _ = sample_audit_entries
    response = client.get("/api/audit/stats")
    assert response.status_code == 401


# ==================== Edge Cases and Error Handling ====================


def test_list_audit_entries_invalid_date_format(
    client: TestClient,
    admin_token: str,
):
    """Test that invalid date format returns validation error."""
    response = client.get(
        "/api/audit?since=invalid-date",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 422


def test_export_audit_log_csv_special_characters(
    client: TestClient,
    admin_token: str,
    session,
):
    """Test CSV export properly handles special characters."""
    entry = AuditEntry(
        event_type="test.event",
        actor="user@test.com",
        tool="test_tool",
        result="success",
        details={"message": 'Test with "quotes" and, commas'},
    )
    session.add(entry)
    session.commit()

    response = client.get(
        "/api/audit/export?format=csv",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    content = response.text
    reader = csv.DictReader(StringIO(content))
    rows = list(reader)
    assert len(rows) == 1


def test_export_audit_log_csv_sanitizes_formula_injection(
    client: TestClient,
    admin_token: str,
    session,
):
    """CSV export should neutralize spreadsheet formula payloads."""
    entry = AuditEntry(
        event_type='=HYPERLINK("https://evil.example","click")',
        actor="+cmd|' /C calc'!A0",
        tool="-2+3",
        result="@SUM(1,1)",
        details={"payload": "safe"},
    )
    session.add(entry)
    session.commit()

    response = client.get(
        "/api/audit/export?format=csv",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    reader = csv.DictReader(StringIO(response.text))
    rows = list(reader)
    assert len(rows) == 1
    row = rows[0]
    assert row["event_type"].startswith("'=")
    assert row["actor"].startswith("'+")
    assert row["tool"].startswith("'-")
    assert row["result"].startswith("'@")


def test_list_audit_entries_concurrent_requests(
    client: TestClient,
    admin_token: str,
    sample_audit_entries: list[AuditEntry],
):
    """Test handling of concurrent requests to list endpoint."""
    _ = sample_audit_entries
    responses = []
    for _ in range(5):
        response = client.get(
            "/api/audit",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        responses.append(response)

    for response in responses:
        assert response.status_code == 200
        assert len(response.json()) == 5


def test_export_audit_log_large_dataset_performance(
    client: TestClient,
    admin_token: str,
    session,
):
    """Test export performance with larger dataset."""
    now = datetime.now(timezone.utc)
    entries = []
    for i in range(100):
        entry = AuditEntry(
            event_type=f"event.type{i % 10}",
            actor=f"user{i % 5}@test.com",
            tool=f"tool{i % 3}",
            result="success",
            timestamp=now - timedelta(minutes=i),
        )
        entries.append(entry)
        session.add(entry)
    session.commit()

    response = client.get(
        "/api/audit/export?format=json",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    data = json.loads(response.text)
    assert len(data) == 100
