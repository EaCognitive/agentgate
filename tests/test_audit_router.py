"""Tests for audit log router list, filter, and lookup endpoints.

This test suite covers:
- GET /audit - list audit entries with filters
- GET /audit/event-types - list distinct event types
- GET /audit/actors - list distinct actors

Includes tests for:
- Authentication/authorization (AUDIT_READ permissions)
- Filter parameters (event_type, actor, tool, since, until)
- Pagination (limit, offset)

Export, statistics, and edge-case tests are in test_audit_router_export.py.
"""

from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import AuditEntry

pytest_plugins = (
    "tests.router_test_support",
    "tests.audit_router_test_support",
)


# ==================== GET /audit Tests ====================


def test_list_audit_entries_success(
    client: TestClient, admin_token: str, sample_audit_entries: list[AuditEntry]
):
    """Test listing all audit entries with admin permissions."""
    _ = sample_audit_entries
    response = client.get(
        "/api/audit",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 5
    # Should be ordered by timestamp descending (most recent first)
    assert data[0]["event_type"] == "user.logout"
    assert data[-1]["event_type"] == "tool.execute"


def test_list_audit_entries_auditor_permission(
    client: TestClient, auditor_token: str, sample_audit_entries: list[AuditEntry]
):
    """Test auditor can call AUDIT_READ endpoint with scoped results."""
    _ = sample_audit_entries
    response = client.get(
        "/api/audit",
        headers={"Authorization": f"Bearer {auditor_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 0


def test_list_audit_entries_unauthorized(client: TestClient):
    """Test that listing audit entries requires authentication."""
    response = client.get("/api/audit")
    assert response.status_code == 401


def test_list_audit_entries_forbidden(
    client: TestClient, viewer_token: str, sample_audit_entries: list[AuditEntry]
):
    """Test that viewer role does not have AUDIT_READ permission."""
    _ = sample_audit_entries
    response = client.get(
        "/api/audit",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )

    assert response.status_code == 403
    assert "Permission required" in response.json()["detail"]


def test_list_audit_entries_filter_by_event_type(
    client: TestClient, admin_token: str, sample_audit_entries: list[AuditEntry]
):
    """Test filtering audit entries by event type."""
    _ = sample_audit_entries
    response = client.get(
        "/api/audit?event_type=tool.execute",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 3
    assert all(entry["event_type"] == "tool.execute" for entry in data)


def test_list_audit_entries_filter_by_actor(
    client: TestClient, admin_token: str, sample_audit_entries: list[AuditEntry]
):
    """Test filtering audit entries by actor."""
    _ = sample_audit_entries
    response = client.get(
        "/api/audit?actor=user1@test.com",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    assert all(entry["actor"] == "user1@test.com" for entry in data)


def test_list_audit_entries_filter_by_tool(
    client: TestClient, admin_token: str, sample_audit_entries: list[AuditEntry]
):
    """Test filtering audit entries by tool."""
    _ = sample_audit_entries
    response = client.get(
        "/api/audit?tool=read_file",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    assert all(entry["tool"] == "read_file" for entry in data)


def test_list_audit_entries_filter_by_since(
    client: TestClient, admin_token: str, sample_audit_entries: list[AuditEntry]
):
    """Test filtering audit entries by since timestamp."""
    _ = sample_audit_entries

    since_dt = datetime.now(timezone.utc) - timedelta(hours=1)
    since = since_dt.isoformat()
    response = client.get(
        f"/api/audit?since={quote(since)}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    # Should only return entries from the last hour
    # (3 entries: login at 30min, read_file at 10min, logout at 5min)
    # The entry at exactly 1 hour ago may or may not be included
    # depending on precision
    assert len(data) >= 3
    for entry in data:
        entry_ts = entry["timestamp"]
        # Handle both with and without timezone info
        if "Z" in entry_ts or "+" in entry_ts:
            entry_time = datetime.fromisoformat(entry_ts.replace("Z", "+00:00"))
        else:
            entry_time = datetime.fromisoformat(entry_ts).replace(tzinfo=timezone.utc)
        assert entry_time >= since_dt


def test_list_audit_entries_filter_by_until(
    client: TestClient, admin_token: str, sample_audit_entries: list[AuditEntry]
):
    """Test filtering audit entries by until timestamp."""
    _ = sample_audit_entries

    until = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    response = client.get(
        f"/api/audit?until={quote(until)}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    # Should only return entries older than 1 hour
    assert len(data) == 2


def test_list_audit_entries_filter_combined(
    client: TestClient, admin_token: str, sample_audit_entries: list[AuditEntry]
):
    """Test combining multiple filters."""
    _ = sample_audit_entries
    response = client.get(
        "/api/audit?event_type=tool.execute&actor=user1@test.com&tool=read_file",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    assert all(
        entry["event_type"] == "tool.execute"
        and entry["actor"] == "user1@test.com"
        and entry["tool"] == "read_file"
        for entry in data
    )


def test_list_audit_entries_pagination_limit(
    client: TestClient, admin_token: str, sample_audit_entries: list[AuditEntry]
):
    """Test pagination with limit parameter."""
    _ = sample_audit_entries
    response = client.get(
        "/api/audit?limit=2",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    # Should return most recent entries first
    assert data[0]["event_type"] == "user.logout"


def test_list_audit_entries_pagination_offset(
    client: TestClient, admin_token: str, sample_audit_entries: list[AuditEntry]
):
    """Test pagination with offset parameter."""
    _ = sample_audit_entries
    response = client.get(
        "/api/audit?limit=2&offset=2",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    # Should skip first 2 entries
    assert data[0]["event_type"] == "user.login"


def test_list_audit_entries_limit_max_validation(
    client: TestClient, admin_token: str, sample_audit_entries: list[AuditEntry]
):
    """Test that limit parameter has a maximum value of 1000."""
    _ = sample_audit_entries
    response = client.get(
        "/api/audit?limit=2000",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    # Should return validation error
    assert response.status_code == 422


def test_list_audit_entries_empty_result(client: TestClient, admin_token: str):
    """Test listing audit entries when none exist."""
    response = client.get(
        "/api/audit",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 0


# ==================== GET /audit/event-types Tests ====================


def test_list_event_types_success(
    client: TestClient, admin_token: str, sample_audit_entries: list[AuditEntry]
):
    """Test listing distinct event types."""
    _ = sample_audit_entries
    response = client.get(
        "/api/audit/event-types",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert "event_types" in data
    event_types = data["event_types"]
    assert len(event_types) == 3
    assert set(event_types) == {"tool.execute", "user.login", "user.logout"}


def test_list_event_types_empty(client: TestClient, admin_token: str):
    """Test listing event types when no audit entries exist."""
    response = client.get(
        "/api/audit/event-types",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert "event_types" in data
    assert len(data["event_types"]) == 0


def test_list_event_types_requires_authentication(
    client: TestClient, sample_audit_entries: list[AuditEntry]
):
    """Test that listing event types requires authentication."""
    _ = sample_audit_entries
    response = client.get("/api/audit/event-types")
    assert response.status_code == 401


# ==================== GET /audit/actors Tests ====================


def test_list_actors_success(
    client: TestClient, admin_token: str, sample_audit_entries: list[AuditEntry]
):
    """Test listing distinct actors."""
    _ = sample_audit_entries
    response = client.get(
        "/api/audit/actors",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert "actors" in data
    actors = data["actors"]
    assert len(actors) == 3
    assert set(actors) == {"user1@test.com", "user2@test.com", "admin@test.com"}


def test_list_actors_excludes_null(client: TestClient, session: Session, admin_token: str):
    """Test that actors list excludes entries with null actor."""
    # Create entries with and without actors
    entries = [
        AuditEntry(event_type="system.start", actor=None),
        AuditEntry(event_type="user.login", actor="user@test.com"),
    ]
    for entry in entries:
        session.add(entry)
    session.commit()

    response = client.get(
        "/api/audit/actors",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    actors = data["actors"]
    assert len(actors) == 1
    assert actors[0] == "user@test.com"


def test_list_actors_empty(client: TestClient, admin_token: str):
    """Test listing actors when no audit entries exist."""
    response = client.get(
        "/api/audit/actors",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert "actors" in data
    assert len(data["actors"]) == 0


def test_list_actors_requires_authentication(
    client: TestClient, sample_audit_entries: list[AuditEntry]
):
    """Test that listing actors requires authentication."""
    _ = sample_audit_entries
    response = client.get("/api/audit/actors")
    assert response.status_code == 401
