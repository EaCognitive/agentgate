"""Extended SQL Injection Security Tests for AgentGate - Approval, Dataset, and Edge Cases.

This module contains additional SQL injection tests for:
- Approval endpoints
- Dataset endpoints
- Test case and test run endpoints
- Edge case scenarios

These tests validate that AgentGate is resistant to SQL injection attacks
across these specific API endpoints.

SUCCESS CRITERIA: All tests should return proper error codes (4xx) without
exposing SQL errors (500) or allowing unauthorized data access.
"""

from fastapi.testclient import TestClient

from server.models import Approval, Dataset, User

pytest_plugins = ("tests.security.sql_injection_test_support",)


# =============================================================================
# APPROVAL ENDPOINTS SQL INJECTION TESTS (10 tests)
# =============================================================================


def test_sql_injection_approval_id_get(
    client: TestClient, auth_token: str, test_approval: Approval
) -> None:
    """Test SQL injection in approval ID parameter."""
    _ = test_approval
    malicious_id = "approval-123' OR '1'='1"
    response = client.get(
        f"/api/approvals/{malicious_id}",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert response.status_code == 404
    assert "SQL" not in response.text.upper()


def test_sql_injection_approval_status_filter(
    client: TestClient, auth_token: str, test_approval: Approval
) -> None:
    """Test SQL injection in approval status filter."""
    _ = test_approval
    malicious_status = "pending' UNION SELECT * FROM users--"
    response = client.get(
        f"/api/approvals?status={malicious_status}",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    # Should return validation error for invalid enum
    assert response.status_code == 422


def test_sql_injection_approval_decide_endpoint(
    client: TestClient, auth_token: str, test_approval: Approval
) -> None:
    """Test SQL injection in approval decision endpoint."""
    _ = test_approval
    malicious_id = "approval-123'; DROP TABLE approvals--"
    response = client.post(
        f"/api/approvals/{malicious_id}/decide",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "approved": True,
            "reason": "Test",
        },
    )
    assert response.status_code == 404
    # Verify approvals table still exists
    response = client.get(
        "/api/approvals",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert response.status_code == 200


def test_sql_injection_approval_decision_reason(
    client: TestClient, auth_token: str, test_approval: Approval
) -> None:
    """Test SQL injection in approval decision reason field.

    System should either block (400) or accept (200) without executing SQL.
    """
    _ = test_approval
    response = client.post(
        f"/api/approvals/{test_approval.approval_id}/decide",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "approved": True,
            "reason": "'; DELETE FROM approvals--",
        },
    )
    # Should either block (400) or succeed (200) without executing SQL
    assert response.status_code in [200, 400]
    if response.status_code == 200:
        data = response.json()
        # Verify approval was updated (status changed from pending)
        assert data["status"] == "approved"
    # Verify approvals table still exists
    response = client.get(
        "/api/approvals",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert response.status_code == 200


def test_sql_injection_approval_create_tool_field(client: TestClient, auth_token: str) -> None:
    """Test SQL injection in approval creation tool field.

    System should either block (400) or accept (200/201) without executing SQL.
    """
    response = client.post(
        "/api/approvals",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "approval_id": "approval-456",
            "agent_id": "agent-1",
            "tool": "delete_file' OR '1'='1",
            "inputs": {"path": "/test"},
            "status": "pending",
        },
    )
    assert response.status_code in [200, 201, 400]
    if response.status_code in [200, 201]:
        data = response.json()
        assert data["tool"] == "delete_file' OR '1'='1"


def test_sql_injection_approval_create_agent_id(client: TestClient, auth_token: str) -> None:
    """Test SQL injection in approval creation agent_id field.

    System should either block (400) or accept (200/201) without executing SQL.
    """
    response = client.post(
        "/api/approvals",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "approval_id": "approval-789",
            "agent_id": "'; DROP TABLE approvals--",
            "tool": "test_tool",
            "inputs": {},
            "status": "pending",
        },
    )
    assert response.status_code in [200, 201, 400]


def test_sql_injection_approval_create_inputs_json(client: TestClient, auth_token: str) -> None:
    """Test SQL injection in approval inputs JSON."""
    response = client.post(
        "/api/approvals",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "approval_id": "approval-999",
            "agent_id": "agent-1",
            "tool": "test_tool",
            "inputs": {
                "malicious": "' UNION SELECT password FROM users--",
            },
            "status": "pending",
        },
    )
    assert response.status_code in [200, 201]
    data = response.json()
    assert data["inputs"]["malicious"] == "' UNION SELECT password FROM users--"


def test_sql_injection_approval_pending_count(
    client: TestClient, auth_token: str, test_approval: Approval
) -> None:
    """Test SQL injection in pending count endpoint."""
    _ = test_approval
    response = client.get(
        "/api/approvals/pending/count",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert response.status_code == 200
    assert "count" in response.json()


def test_sql_injection_approval_list_limit_offset(
    client: TestClient, auth_token: str, test_approval: Approval
) -> None:
    """Test SQL injection in approval list limit/offset."""
    _ = test_approval
    response = client.get(
        "/api/approvals?limit=50' OR '1'='1",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert response.status_code == 422


def test_sql_injection_approval_id_path_traversal(
    client: TestClient, auth_token: str, test_approval: Approval
) -> None:
    """Test SQL injection combined with path traversal in approval ID."""
    _ = test_approval
    malicious_id = "../../users/1' OR '1'='1"
    response = client.get(
        f"/api/approvals/{malicious_id}",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert response.status_code == 404


# =============================================================================
# DATASET ENDPOINTS SQL INJECTION TESTS (10 tests)
# =============================================================================


def test_sql_injection_dataset_name_create(client: TestClient, auth_token: str) -> None:
    """Test SQL injection in dataset name field during creation.

    System should either block (400) or accept (201) without executing SQL.
    """
    response = client.post(
        "/api/datasets",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "name": "Test Dataset'; DROP TABLE datasets--",
            "description": "Test description",
        },
    )
    assert response.status_code in [201, 400]
    if response.status_code == 201:
        data = response.json()
        # Verify name stored as-is, not executed
        assert data["name"] == "Test Dataset'; DROP TABLE datasets--"
    # Verify datasets table still exists
    response = client.get(
        "/api/datasets",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert response.status_code == 200


def test_sql_injection_dataset_description_create(client: TestClient, auth_token: str) -> None:
    """Test SQL injection in dataset description field.

    System should either block (400) or accept (201) without executing SQL.
    """
    response = client.post(
        "/api/datasets",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "name": "Test Dataset",
            "description": "' UNION SELECT * FROM users--",
        },
    )
    assert response.status_code in [201, 400]
    if response.status_code == 201:
        data = response.json()
        assert data["description"] == "' UNION SELECT * FROM users--"


def test_sql_injection_dataset_id_get(
    client: TestClient, auth_token: str, test_dataset: Dataset
) -> None:
    """Test SQL injection in dataset ID parameter."""
    _ = test_dataset
    malicious_id = "1' OR '1'='1"
    response = client.get(
        f"/api/datasets/{malicious_id}",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    # Should return validation error for non-integer ID
    assert response.status_code == 422


def test_sql_injection_dataset_update_name(
    client: TestClient, auth_token: str, test_dataset: Dataset
) -> None:
    """Test SQL injection in dataset update name field.

    System should either block (400) or accept (200) without executing SQL.
    """
    _ = test_dataset
    response = client.patch(
        f"/api/datasets/{test_dataset.id}",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "name": "Updated'; DELETE FROM datasets--",
        },
    )
    assert response.status_code in [200, 400]
    if response.status_code == 200:
        data = response.json()
        assert data["name"] == "Updated'; DELETE FROM datasets--"


def test_sql_injection_dataset_tags_array(client: TestClient, auth_token: str) -> None:
    """Test SQL injection in dataset tags array field."""
    response = client.post(
        "/api/datasets",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "name": "Tagged Dataset",
            "description": "Test",
            "tags": [
                "normal-tag",
                "'; DROP TABLE datasets--",
                "' OR '1'='1",
            ],
        },
    )
    assert response.status_code == 201
    data = response.json()
    # Tags should be stored as-is
    assert "'; DROP TABLE datasets--" in data["tags"]


def test_sql_injection_test_case_name(
    client: TestClient, auth_token: str, test_dataset: Dataset
) -> None:
    """Test SQL injection in test case name field.

    System should either:
    1. Block the request (400) via threat detection
    2. Sanitize and store (201) as literal string
    """
    _ = test_dataset
    response = client.post(
        f"/api/datasets/{test_dataset.id}/tests",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "dataset_id": test_dataset.id,
            "name": "Test Case'; DROP TABLE test_cases--",
            "description": "Test",
            "tool": "test_tool",
            "inputs": {},
        },
    )
    # Should either block (400) or accept (201), not execute SQL (500)
    assert response.status_code in [201, 400]
    if response.status_code == 201:
        data = response.json()
        assert data["name"] == "Test Case'; DROP TABLE test_cases--"


def test_sql_injection_test_case_tool_filter(
    client: TestClient, auth_token: str, test_dataset: Dataset
) -> None:
    """Test SQL injection in test case tool filter."""
    _ = test_dataset
    response = client.get(
        f"/api/datasets/{test_dataset.id}/tests?tool=test_tool' OR '1'='1",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    # Should return empty list (no matches)
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_sql_injection_test_case_inputs_json(
    client: TestClient, auth_token: str, test_dataset: Dataset
) -> None:
    """Test SQL injection in test case inputs JSON.

    System should either block or sanitize, not execute SQL.
    """
    _ = test_dataset
    response = client.post(
        f"/api/datasets/{test_dataset.id}/tests",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "name": "Test Case",
            "description": "Test",
            "tool": "test_tool",
            "inputs": {
                "query": "'; DELETE FROM test_cases--",
                "filter": "' OR '1'='1",
            },
        },
    )
    # Should either block (400), validation error (422), or accept (201), not execute SQL (500)
    assert response.status_code in [201, 400, 422]
    if response.status_code == 201:
        data = response.json()
        assert data["inputs"]["query"] == "'; DELETE FROM test_cases--"


def test_sql_injection_test_case_expected_output(
    client: TestClient, auth_token: str, test_dataset: Dataset
) -> None:
    """Test SQL injection in test case expected_output field.

    System should either block or sanitize, not execute SQL.
    """
    _ = test_dataset
    response = client.post(
        f"/api/datasets/{test_dataset.id}/tests",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "dataset_id": test_dataset.id,
            "name": "Test Case",
            "description": "Test",
            "tool": "test_tool",
            "inputs": {},
            "expected_output": {"malicious": "' UNION SELECT password FROM users--"},
        },
    )
    # Should either block (400) or accept (201), not execute SQL (500)
    assert response.status_code in [201, 400]
    if response.status_code == 201:
        data = response.json()
        assert data["expected_output"]["malicious"] == "' UNION SELECT password FROM users--"


def test_sql_injection_test_case_from_trace_id(
    client: TestClient, auth_token: str, test_dataset: Dataset
) -> None:
    """Test SQL injection in test case from trace endpoint.

    System should either block (400), return not found (404),
    or validation error (422), not execute SQL.
    """
    _ = test_dataset
    malicious_trace_id = "test-trace-123'; DROP TABLE test_cases--"
    response = client.post(
        f"/api/datasets/{test_dataset.id}/tests/from-trace",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "trace_id": malicious_trace_id,
            "name": "Test from trace",
        },
    )
    # Should either block (400), return not found (404), or
    # validation error (422), not execute SQL (500)
    assert response.status_code in [400, 404, 422]


# =============================================================================
# ADDITIONAL EDGE CASE TESTS (6 tests)
# =============================================================================


def test_sql_injection_register_email(client: TestClient) -> None:
    """Test SQL injection in user registration email field."""
    response = client.post(
        "/api/auth/register",
        json={
            "email": "test'; DROP TABLE users--@example.com",
            "password": "password123",
            "name": "Test User",
        },
    )
    # Should either succeed (stored as-is) or fail validation
    assert response.status_code in [200, 400, 422]
    if response.status_code == 200:
        data = response.json()
        assert "DROP TABLE" in data["email"]


def test_sql_injection_refresh_token(client: TestClient, test_user: User) -> None:
    """Test SQL injection in refresh token field.

    System should either block (400) or return invalid token (401).
    """
    _ = test_user
    response = client.post(
        "/api/auth/refresh",
        json={
            "refresh_token": "token' OR '1'='1--",
        },
    )
    # Should return 400 (blocked) or 401 (invalid token)
    assert response.status_code in [400, 401]


def test_sql_injection_check_mfa_email(client: TestClient, test_user: User) -> None:
    """Test SQL injection in check MFA status email parameter.

    System should either block (400), return success (200), or validation error (422).
    """
    _ = test_user
    response = client.post(
        "/api/auth/check-mfa",
        json={"email": "test@example.com' OR '1'='1--"},
    )
    # Should return 400 (blocked), 200 (success), or 422 (validation error)
    assert response.status_code in [200, 400, 422]


def test_sql_injection_dataset_metadata_json(client: TestClient, auth_token: str) -> None:
    """Test SQL injection in dataset metadata_json field.

    System should either block or sanitize, not execute SQL.
    Note: metadata_json may not be in the response model, so we just verify
    the request doesn't cause SQL errors.
    """
    response = client.post(
        "/api/datasets",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "name": "Test Dataset Metadata",
            "description": "Test",
            "metadata_json": {
                "key": "'; DROP TABLE datasets--",
                "nested": {"value": "' OR '1'='1"},
            },
        },
    )
    # Should either block (400) or accept (201), not execute SQL (500)
    assert response.status_code in [201, 400]
    if response.status_code == 201:
        # Just verify dataset was created without SQL error
        data = response.json()
        assert data["name"] == "Test Dataset Metadata"


def test_sql_injection_test_run_name(
    client: TestClient, auth_token: str, test_dataset: Dataset
) -> None:
    """Test SQL injection in test run name field.

    System should either block or sanitize, not execute SQL.
    """
    _ = test_dataset
    response = client.post(
        f"/api/datasets/{test_dataset.id}/runs",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "dataset_id": test_dataset.id,
            "name": "Test Run'; DELETE FROM test_runs--",
            "config": {},
        },
    )
    # Should either block (400) or accept (201), not execute SQL (500)
    assert response.status_code in [201, 400]
    if response.status_code == 201:
        data = response.json()
        assert data["name"] == "Test Run'; DELETE FROM test_runs--"


def test_sql_injection_trace_id_special_chars(client: TestClient, auth_token: str) -> None:
    """Test SQL injection with special characters in trace ID.

    System should either block (400) or handle special characters safely.
    """
    special_chars_id = "trace-123';--\x00\n\r\t"
    response = client.post(
        "/api/traces",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "trace_id": special_chars_id,
            "agent_id": "agent-1",
            "tool": "test_tool",
            "inputs": {},
            "status": "pending",
        },
    )
    # Should either block (400) or handle special characters safely (200/201)
    assert response.status_code in [200, 201, 400]
    if response.status_code in [200, 201]:
        data = response.json()
        # Verify trace_id is stored (may be sanitized)
        assert "trace_id" in data
