"""Comprehensive SQL Injection Security Tests for AgentGate.

This test suite validates that AgentGate is resistant to SQL injection attacks
across all API endpoints. Tests cover:
- Login/authentication endpoints
- Trace endpoints
- Approval endpoints
- Dataset endpoints
- All query parameters and request bodies

SUCCESS CRITERIA: All tests should return proper error codes (4xx) without
exposing SQL errors (500) or allowing unauthorized data access.
"""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import Trace, TraceStatus, User

pytest_plugins = ("tests.security.sql_injection_test_support",)


@pytest.fixture(name="test_trace")
def test_trace_fixture(session: Session) -> Trace:
    """Create a test trace in the database."""
    trace = Trace(
        trace_id="test-trace-123",
        agent_id="agent-1",
        tool="read_file",
        inputs={"path": "/test/file.txt"},
        output={"result": "file contents"},  # Output must be dict for API validation
        status=TraceStatus.SUCCESS,
        started_at=datetime.now(timezone.utc),
        duration_ms=100,
    )
    session.add(trace)
    session.commit()
    session.refresh(trace)
    return trace


# =============================================================================
# LOGIN ENDPOINT SQL INJECTION TESTS (10 tests)
# =============================================================================


def test_sql_injection_login_email_classic_or(client: TestClient, test_user: User) -> None:
    """Test classic SQL injection with OR '1'='1' in email field.

    System should either:
    1. Block the request (400) via threat detection
    2. Return unauthorized (401) if payload passes validation
    NOT return 500 (SQL error).
    """
    _ = test_user
    malicious_email = "admin' OR '1'='1"
    response = client.post(
        "/api/auth/login",
        json={
            "email": malicious_email,
            "password": "test",
        },
    )
    # Should return 400 (blocked) or 401 (unauthorized), NOT 500 (SQL error)
    assert response.status_code in [400, 401]
    # Response should not contain SQL keywords
    response_text = response.text.upper()
    assert "DROP" not in response_text
    assert "SELECT" not in response_text
    assert "UNION" not in response_text


def test_sql_injection_login_email_comment(client: TestClient, test_user: User) -> None:
    """Test SQL injection with comment syntax (admin'--)."""
    _ = test_user
    malicious_email = "admin'--"
    response = client.post(
        "/api/auth/login",
        json={
            "email": malicious_email,
            "password": "test",
        },
    )
    assert response.status_code in [400, 401]
    assert "DROP" not in response.text.upper()


def test_sql_injection_login_email_union(client: TestClient, test_user: User) -> None:
    """Test UNION-based SQL injection in email field."""
    _ = test_user
    malicious_email = "' UNION SELECT * FROM users --"
    response = client.post(
        "/api/auth/login",
        json={
            "email": malicious_email,
            "password": "test",
        },
    )
    assert response.status_code in [400, 401]
    assert "UNION" not in response.text.upper()


def test_sql_injection_login_email_drop_table(client: TestClient, test_user: User) -> None:
    """Test DROP TABLE SQL injection in email field."""
    _ = test_user
    malicious_email = "'; DROP TABLE users; --"
    response = client.post(
        "/api/auth/login",
        json={
            "email": malicious_email,
            "password": "test",
        },
    )
    assert response.status_code in [400, 401]
    # Verify user table still exists (can still query it)
    response = client.post(
        "/api/auth/login",
        json={
            "email": "test@example.com",
            "password": "password123",
        },
    )
    assert response.status_code == 200  # User table intact


def test_sql_injection_login_email_boolean_based(client: TestClient, test_user: User) -> None:
    """Test boolean-based blind SQL injection (AND 1=1--)."""
    _ = test_user
    malicious_email = "admin' AND 1=1--"
    response = client.post(
        "/api/auth/login",
        json={
            "email": malicious_email,
            "password": "test",
        },
    )
    assert response.status_code in [400, 401]


def test_sql_injection_login_email_nested_or(client: TestClient, test_user: User) -> None:
    """Test nested OR condition SQL injection."""
    _ = test_user
    malicious_email = "' OR 'x'='x"
    response = client.post(
        "/api/auth/login",
        json={
            "email": malicious_email,
            "password": "test",
        },
    )
    assert response.status_code in [400, 401]


def test_sql_injection_login_email_multiline_comment(client: TestClient, test_user: User) -> None:
    """Test multiline comment SQL injection (admin' /**/)."""
    _ = test_user
    malicious_email = "admin' /*"
    response = client.post(
        "/api/auth/login",
        json={
            "email": malicious_email,
            "password": "test",
        },
    )
    assert response.status_code in [400, 401]


def test_sql_injection_login_email_hash_comment(client: TestClient, test_user: User) -> None:
    """Test MySQL hash comment SQL injection (' OR 1=1#)."""
    _ = test_user
    malicious_email = "' OR 1=1#"
    response = client.post(
        "/api/auth/login",
        json={
            "email": malicious_email,
            "password": "test",
        },
    )
    assert response.status_code in [400, 401]


def test_sql_injection_login_password_field(client: TestClient, test_user: User) -> None:
    """Test SQL injection in password field."""
    _ = test_user
    malicious_password = "' OR '1'='1"
    response = client.post(
        "/api/auth/login",
        json={
            "email": "test@example.com",
            "password": malicious_password,
        },
    )
    assert response.status_code in [400, 401]


def test_sql_injection_login_combined_fields(client: TestClient, test_user: User) -> None:
    """Test SQL injection in both email and password fields."""
    _ = test_user
    response = client.post(
        "/api/auth/login",
        json={
            "email": "admin' OR '1'='1",
            "password": "' OR '1'='1",
        },
    )
    assert response.status_code in [400, 401]


# =============================================================================
# TRACE ENDPOINTS SQL INJECTION TESTS (10 tests)
# =============================================================================


def test_sql_injection_trace_id_get(client: TestClient, auth_token: str, test_trace: Trace) -> None:
    """Test SQL injection in trace ID parameter (GET /traces/{trace_id})."""
    _ = test_trace
    malicious_id = "test' OR '1'='1"
    response = client.get(
        f"/api/traces/{malicious_id}",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    # Should return 404, not expose SQL
    assert response.status_code == 404
    assert "SQL" not in response.text.upper()


def test_sql_injection_trace_status_filter(
    client: TestClient, auth_token: str, test_trace: Trace
) -> None:
    """Test SQL injection in trace status query parameter."""
    _ = test_trace
    malicious_status = "success' OR '1'='1"
    response = client.get(
        f"/api/traces?status={malicious_status}",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    # Should return validation error (422) for invalid enum value
    assert response.status_code == 422


def test_sql_injection_trace_tool_filter(
    client: TestClient, auth_token: str, test_trace: Trace
) -> None:
    """Test SQL injection in trace tool filter parameter."""
    _ = test_trace
    malicious_tool = "read_file' UNION SELECT * FROM users--"
    response = client.get(
        f"/api/traces?tool={malicious_tool}",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    # Should return empty list (no matches), not SQL error
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_sql_injection_trace_agent_id_filter(
    client: TestClient, auth_token: str, test_trace: Trace
) -> None:
    """Test SQL injection in trace agent_id filter parameter."""
    _ = test_trace
    malicious_agent = "agent-1'; DROP TABLE traces--"
    response = client.get(
        f"/api/traces?agent_id={malicious_agent}",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert response.status_code == 200
    # Verify traces table still exists
    response = client.get(
        "/api/traces",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert response.status_code == 200


def test_sql_injection_trace_stats_hours_param(
    client: TestClient, auth_token: str, test_trace: Trace
) -> None:
    """Test SQL injection in trace stats hours parameter."""
    _ = test_trace
    malicious_hours = "24 OR 1=1"
    response = client.get(
        f"/api/traces/stats?hours={malicious_hours}",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    # Should return validation error for non-integer
    assert response.status_code == 422


def test_sql_injection_trace_timeline_bucket(
    client: TestClient, auth_token: str, test_trace: Trace
) -> None:
    """Test SQL injection in timeline bucket_minutes parameter."""
    _ = test_trace
    malicious_bucket = "60'; DELETE FROM traces--"
    response = client.get(
        f"/api/traces/timeline?bucket_minutes={malicious_bucket}",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    # Should return validation error
    assert response.status_code == 422


def test_sql_injection_trace_create_tool_name(client: TestClient, auth_token: str) -> None:
    """Test SQL injection in trace creation tool field.

    System should either block (400) or accept (200/201) as literal value.
    """
    response = client.post(
        "/api/traces",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "trace_id": "trace-123",
            "agent_id": "agent-1",
            "tool": "read_file' OR '1'='1",
            "inputs": {"path": "/test"},
            "status": "pending",
        },
    )
    # Should either block (400) or create trace (200/201)
    assert response.status_code in [200, 201, 400]
    if response.status_code in [200, 201]:
        # Verify it's stored as-is, not executed
        data = response.json()
        assert data["tool"] == "read_file' OR '1'='1"


def test_sql_injection_trace_create_agent_id(client: TestClient, auth_token: str) -> None:
    """Test SQL injection in trace creation agent_id field.

    System should either block (400) or accept (200/201) without executing SQL.
    """
    response = client.post(
        "/api/traces",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "trace_id": "trace-456",
            "agent_id": "'; DROP TABLE traces--",
            "tool": "test_tool",
            "inputs": {},
            "status": "pending",
        },
    )
    assert response.status_code in [200, 201, 400]
    # Verify traces table still exists
    response = client.get(
        "/api/traces",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert response.status_code == 200


def test_sql_injection_trace_create_inputs_json(client: TestClient, auth_token: str) -> None:
    """Test SQL injection in trace inputs JSON field."""
    response = client.post(
        "/api/traces",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "trace_id": "trace-789",
            "agent_id": "agent-1",
            "tool": "test_tool",
            "inputs": {"malicious": "'; DELETE FROM traces--", "path": "test' OR '1'='1"},
            "status": "pending",
        },
    )
    assert response.status_code in [200, 201]
    # Verify data stored as-is
    data = response.json()
    assert data["inputs"]["malicious"] == "'; DELETE FROM traces--"


def test_sql_injection_trace_search_limit_offset(
    client: TestClient, auth_token: str, test_trace: Trace
) -> None:
    """Test SQL injection in limit and offset parameters."""
    _ = test_trace
    response = client.get(
        "/api/traces?limit=10' OR '1'='1&offset=0",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    # Should return validation error
    assert response.status_code == 422


# =============================================================================
# SUMMARY
# =============================================================================

# Test Coverage Summary:
#
# This file contains core SQL injection tests for LOGIN and TRACE endpoints.
# Additional tests for APPROVAL, DATASET, and EDGE CASES have been moved to:
#   tests/security/test_sql_injection_extended.py
#
# LOGIN ENDPOINTS (10 tests):
# - Classic OR injection in email
# - Comment-based injection
# - UNION SELECT injection
# - DROP TABLE injection
# - Boolean-based blind injection
# - Nested OR conditions
# - Multiline comments
# - Hash comments
# - Password field injection
# - Combined field injection
#
# TRACE ENDPOINTS (10 tests):
# - Trace ID path parameter
# - Status filter query param
# - Tool filter query param
# - Agent ID filter
# - Stats hours parameter
# - Timeline bucket parameter
# - Create trace tool field
# - Create trace agent_id field
# - Create trace inputs JSON
# - Limit/offset parameters
#
# EXTENDED TESTS (in test_sql_injection_extended.py):
# - APPROVAL ENDPOINTS (10 tests)
# - DATASET ENDPOINTS (10 tests)
# - EDGE CASES (6 tests)
#
# TOTAL: 20 TESTS IN THIS FILE + 26 TESTS IN EXTENDED FILE = 46 TESTS
#
# All tests verify that:
# 1. No SQL errors (500) are returned
# 2. Proper error codes (401, 404, 422) are returned
# 3. No SQL keywords appear in responses
# 4. Malicious strings are stored as literals, not executed
# 5. Database tables remain intact after injection attempts
