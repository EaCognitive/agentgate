"""Extended XSS and CSRF security tests for AgentGate.

This module contains extended tests for:
1. XSS protection across various API endpoints (datasets, approvals, test cases)
2. CSRF authentication requirements across all state-changing operations
3. Complex nested payloads and query parameter validation

These tests complement the core XSS/CSRF tests in test_xss_csrf.py.
See test_xss_csrf.py for the security model documentation and fixtures.
"""

from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import (
    Approval,
    ApprovalStatus,
    Dataset,
)
pytest_plugins = ("tests.security.xss_csrf_test_support",)


# ============================================================================
# XSS Tests - Dataset Endpoints
# ============================================================================


def test_xss_dataset_name_field(xss_client: TestClient, xss_auth_headers: dict[str, str]):
    """Test XSS handling in dataset name."""
    xss_payload = "<script>alert('Dataset XSS')</script>"

    response = xss_client.post(
        "/api/datasets",
        headers=xss_auth_headers,
        json={
            "name": xss_payload,
            "description": "Test dataset",
        },
    )
    assert response.status_code == 201
    assert "Content-Security-Policy" in response.headers
    assert "X-XSS-Protection" in response.headers


def test_xss_dataset_description_field(xss_client: TestClient, xss_auth_headers: dict[str, str]):
    """Test XSS handling in dataset description."""
    xss_payload = "<img src=x onerror=alert('XSS')>"

    response = xss_client.post(
        "/api/datasets",
        headers=xss_auth_headers,
        json={
            "name": "Test Dataset",
            "description": xss_payload,
        },
    )
    assert response.status_code == 201
    assert "Content-Security-Policy" in response.headers


def test_xss_dataset_tags_field(xss_client: TestClient, xss_auth_headers: dict[str, str]):
    """Test XSS handling in dataset tags."""
    xss_payload = "<body onload=alert('XSS')>"

    response = xss_client.post(
        "/api/datasets",
        headers=xss_auth_headers,
        json={
            "name": "Test Dataset",
            "description": "Test",
            "tags": [xss_payload, "normal-tag", "javascript:alert(1)"],
        },
    )
    assert response.status_code == 201
    assert "Content-Security-Policy" in response.headers


def test_xss_dataset_metadata_json(xss_client: TestClient, xss_auth_headers: dict[str, str]):
    """Test XSS handling in dataset metadata JSON."""
    xss_payload = "<script>alert(document.cookie)</script>"

    response = xss_client.post(
        "/api/datasets",
        headers=xss_auth_headers,
        json={
            "name": "Test Dataset",
            "description": "Test",
            "metadata_json": {
                "custom_field": xss_payload,
                "nested": {
                    "malicious": "<svg onload=alert(1)>",
                },
            },
        },
    )
    assert response.status_code == 201
    assert "X-XSS-Protection" in response.headers


# ============================================================================
# XSS Tests - Approval Endpoints
# ============================================================================


def test_xss_approval_decision_reason(
    xss_client: TestClient,
    xss_admin_headers: dict[str, str],
    xss_session: Session,
):
    """Test XSS handling in approval decision reason."""
    # Create approval
    approval = Approval(
        approval_id="approval_xss_test_1",
        tool="sensitive_tool",
        inputs={"action": "delete"},
        status=ApprovalStatus.PENDING,
    )
    xss_session.add(approval)
    xss_session.commit()

    xss_payload = "<script>alert('Approval XSS')</script>"

    response = xss_client.post(
        "/api/approvals/approval_xss_test_1/decide",
        headers=xss_admin_headers,
        json={
            "approved": True,
            "reason": xss_payload,
        },
    )
    assert response.status_code == 200
    assert "Content-Security-Policy" in response.headers


def test_xss_approval_tool_name(xss_client: TestClient, xss_admin_headers: dict[str, str]):
    """Test XSS handling in approval tool name."""
    xss_payload = "<img src=x onerror=alert('XSS')>"

    response = xss_client.post(
        "/api/approvals",
        headers=xss_admin_headers,
        json={
            "approval_id": "approval_xss_test_2",
            "tool": xss_payload,
            "inputs": {"test": "data"},
            "requested_by": "user@example.com",
        },
    )
    assert response.status_code == 200
    assert "Content-Security-Policy" in response.headers


def test_xss_approval_inputs_field(xss_client: TestClient, xss_admin_headers: dict[str, str]):
    """Test XSS handling in approval inputs."""
    xss_payload = "javascript:alert(1)"

    response = xss_client.post(
        "/api/approvals",
        headers=xss_admin_headers,
        json={
            "approval_id": "approval_xss_test_3",
            "tool": "test_tool",
            "inputs": {
                "malicious": xss_payload,
                "nested": {"evil": "<svg onload=alert(2)>"},
            },
            "requested_by": "user@example.com",
        },
    )
    assert response.status_code == 200
    assert "X-XSS-Protection" in response.headers


# ============================================================================
# XSS Tests - Test Case Endpoints
# ============================================================================


def test_xss_test_case_name(
    xss_client: TestClient,
    xss_auth_headers: dict[str, str],
    xss_session: Session,
):
    """Test XSS handling in test case name.

    May be rejected by threat detection (422) or accepted with security headers (201).
    """
    dataset = Dataset(
        name="Test Dataset",
        description="Test",
        created_by=1,
    )
    xss_session.add(dataset)
    xss_session.commit()
    xss_session.refresh(dataset)

    xss_payload = "<img src=x onerror=alert('XSS')>"

    response = xss_client.post(
        f"/api/datasets/{dataset.id}/tests",
        headers=xss_auth_headers,
        json={
            "name": xss_payload,
            "description": "Test case",
            "tool": "test_tool",
            "inputs": {"test": "data"},
            "expected_output": {"result": "success"},
        },
    )
    # May be rejected by threat detection or accepted
    assert response.status_code in [201, 422]
    assert "Content-Security-Policy" in response.headers


def test_xss_test_case_description(
    xss_client: TestClient,
    xss_auth_headers: dict[str, str],
    xss_session: Session,
):
    """Test XSS handling in test case description.

    May be rejected by threat detection (422) or accepted with security headers (201).
    """
    dataset = Dataset(
        name="Test Dataset",
        description="Test",
        created_by=1,
    )
    xss_session.add(dataset)
    xss_session.commit()
    xss_session.refresh(dataset)

    xss_payload = "<svg onload=alert('XSS')>"

    response = xss_client.post(
        f"/api/datasets/{dataset.id}/tests",
        headers=xss_auth_headers,
        json={
            "name": "Test Case",
            "description": xss_payload,
            "tool": "test_tool",
            "inputs": {"test": "data"},
            "expected_output": {"result": "success"},
        },
    )
    # May be rejected by threat detection or accepted
    assert response.status_code in [201, 422]
    assert "X-XSS-Protection" in response.headers


def test_xss_test_case_inputs(
    xss_client: TestClient,
    xss_auth_headers: dict[str, str],
    xss_session: Session,
):
    """Test XSS handling in test case inputs.

    May be rejected by threat detection (422) or accepted with security headers (201).
    """
    dataset = Dataset(
        name="Test Dataset",
        description="Test",
        created_by=1,
    )
    xss_session.add(dataset)
    xss_session.commit()
    xss_session.refresh(dataset)

    xss_payload = "<script>alert(document.domain)</script>"

    response = xss_client.post(
        f"/api/datasets/{dataset.id}/tests",
        headers=xss_auth_headers,
        json={
            "name": "Test Case",
            "description": "Test",
            "tool": "test_tool",
            "inputs": {"malicious_input": xss_payload},
            "expected_output": {"result": "success"},
        },
    )
    # May be rejected by threat detection or accepted
    assert response.status_code in [201, 422]
    assert "Content-Security-Policy" in response.headers


def test_xss_test_case_expected_output(
    xss_client: TestClient,
    xss_auth_headers: dict[str, str],
    xss_session: Session,
):
    """Test XSS handling in test case expected output.

    May be rejected by threat detection (422) or accepted with security headers (201).
    """
    dataset = Dataset(
        name="Test Dataset",
        description="Test",
        created_by=1,
    )
    xss_session.add(dataset)
    xss_session.commit()
    xss_session.refresh(dataset)

    xss_payload = "<iframe src='javascript:alert(1)'>"

    response = xss_client.post(
        f"/api/datasets/{dataset.id}/tests",
        headers=xss_auth_headers,
        json={
            "name": "Test Case",
            "description": "Test",
            "tool": "test_tool",
            "inputs": {"test": "data"},
            "expected_output": {"result": xss_payload},
        },
    )
    # May be rejected by threat detection or accepted
    assert response.status_code in [201, 422]
    assert "Content-Security-Policy" in response.headers


# ============================================================================
# XSS Tests - Query Parameters
# ============================================================================


def test_xss_trace_filter_query_params(xss_client: TestClient, xss_auth_headers: dict[str, str]):
    """Test XSS handling in trace filter query parameters."""
    xss_payload = "<script>alert('XSS')</script>"

    response = xss_client.get(
        f"/api/traces?tool={xss_payload}&agent_id={xss_payload}",
        headers=xss_auth_headers,
    )
    # Should succeed or fail validation, but always have security headers
    assert response.status_code in [200, 422]
    assert "Content-Security-Policy" in response.headers


def test_xss_dataset_list_filters(xss_client: TestClient, xss_auth_headers: dict[str, str]):
    """Test XSS handling in dataset list filter parameters."""
    xss_payload = "<img src=x onerror=alert('XSS')>"

    response = xss_client.get(
        f"/api/datasets?limit=10&offset=0&search={xss_payload}",
        headers=xss_auth_headers,
    )
    assert response.status_code in [200, 422]
    assert "Content-Security-Policy" in response.headers


# ============================================================================
# XSS Tests - Complex Nested Payloads
# ============================================================================


def test_xss_nested_json_payload(xss_client: TestClient, xss_auth_headers: dict[str, str]):
    """Test XSS handling in deeply nested JSON structures."""
    xss_payload = "<script>alert('Nested XSS')</script>"

    response = xss_client.post(
        "/api/traces",
        headers=xss_auth_headers,
        json={
            "trace_id": "trace_nested_xss",
            "tool": "test_tool",
            "inputs": {
                "level1": {
                    "level2": {
                        "level3": {
                            "malicious": xss_payload,
                            "deep": {
                                "deeper": "<svg onload=alert(1)>",
                            },
                        }
                    }
                }
            },
            "status": "success",
        },
    )
    assert response.status_code == 200
    assert "Content-Security-Policy" in response.headers


def test_xss_array_of_payloads(xss_client: TestClient, xss_auth_headers: dict[str, str]):
    """Test XSS handling in arrays containing malicious payloads."""
    xss_payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(2)>",
        "javascript:alert(3)",
        "<svg onload=alert(4)>",
        "<iframe src='javascript:alert(5)'>",
    ]

    response = xss_client.post(
        "/api/traces",
        headers=xss_auth_headers,
        json={
            "trace_id": "trace_array_xss",
            "tool": "test_tool",
            "inputs": {"malicious_array": xss_payloads},
            "status": "success",
        },
    )
    assert response.status_code == 200
    assert "Content-Security-Policy" in response.headers
    assert "X-XSS-Protection" in response.headers


# ============================================================================
# CSRF Tests - Authentication Requirements
# ============================================================================


def test_csrf_trace_creation_requires_auth(xss_client: TestClient):
    """Test that trace creation requires authentication."""
    response = xss_client.post(
        "/api/traces",
        json={
            "trace_id": "trace_csrf_test",
            "tool": "test_tool",
            "inputs": {"test": "data"},
            "status": "success",
        },
    )
    # Trace creation requires authentication
    assert response.status_code == 401


def test_csrf_approval_decision_requires_auth(xss_client: TestClient, xss_session: Session):
    """Test that approval decisions require authentication."""
    approval = Approval(
        approval_id="approval_csrf_test",
        tool="test_tool",
        inputs={"action": "test"},
        status=ApprovalStatus.PENDING,
    )
    xss_session.add(approval)
    xss_session.commit()

    # Try to decide without authentication
    response = xss_client.post(
        "/api/approvals/approval_csrf_test/decide",
        json={
            "approved": True,
            "reason": "Test approval",
        },
    )
    assert response.status_code == 401


def test_csrf_dataset_creation_requires_auth(xss_client: TestClient):
    """Test that dataset creation requires authentication."""
    response = xss_client.post(
        "/api/datasets",
        json={
            "name": "Test Dataset",
            "description": "Test",
        },
    )
    assert response.status_code == 401


def test_csrf_dataset_deletion_requires_auth(xss_client: TestClient, xss_session: Session):
    """Test that dataset deletion requires authentication."""
    dataset = Dataset(
        name="Test Dataset",
        description="Test",
        created_by=1,
    )
    xss_session.add(dataset)
    xss_session.commit()
    xss_session.refresh(dataset)

    response = xss_client.delete(f"/api/datasets/{dataset.id}")
    assert response.status_code == 401


def test_csrf_dataset_update_requires_auth(xss_client: TestClient, xss_session: Session):
    """Test that dataset updates require authentication."""
    dataset = Dataset(
        name="Test Dataset",
        description="Test",
        created_by=1,
    )
    xss_session.add(dataset)
    xss_session.commit()
    xss_session.refresh(dataset)

    response = xss_client.patch(
        f"/api/datasets/{dataset.id}",
        json={"name": "Updated Name"},
    )
    assert response.status_code == 401


def test_csrf_user_registration_validation(xss_client: TestClient):
    """Test that user registration validates input properly."""
    response = xss_client.post(
        "/api/auth/register",
        json={
            "email": "csrf_test@example.com",
            "password": "SecurePass123!",
            "name": "CSRF Test User",
        },
    )
    assert response.status_code == 200


def test_csrf_get_requests_work_with_auth(xss_client: TestClient, xss_auth_headers: dict[str, str]):
    """Test that GET requests work with authentication."""
    response = xss_client.get("/api/traces", headers=xss_auth_headers)
    assert response.status_code == 200

    response = xss_client.get("/api/datasets", headers=xss_auth_headers)
    assert response.status_code == 200


def test_csrf_options_requests_allowed(xss_client: TestClient):
    """Test that OPTIONS requests are allowed for CORS preflight."""
    response = xss_client.options("/api/traces")
    assert response.status_code in [200, 405]


def test_csrf_authenticated_requests_succeed(
    xss_client: TestClient,
    xss_auth_headers: dict[str, str],
):
    """Test that authenticated requests bypass CSRF protection."""
    response = xss_client.post(
        "/api/datasets",
        headers=xss_auth_headers,
        json={
            "name": "Test Dataset",
            "description": "Test",
        },
    )
    assert response.status_code == 201


def test_csrf_invalid_token_fails(xss_client: TestClient):
    """Test that invalid JWT tokens are rejected."""
    headers = {"Authorization": "Bearer invalid-token-12345"}

    response = xss_client.post(
        "/api/datasets",
        headers=headers,
        json={
            "name": "Test Dataset",
            "description": "Test",
        },
    )
    assert response.status_code == 401


def test_csrf_malformed_auth_header_fails(xss_client: TestClient):
    """Test that malformed authorization headers are rejected."""
    headers = {"Authorization": "InvalidFormat token123"}

    response = xss_client.post(
        "/api/datasets",
        headers=headers,
        json={
            "name": "Test Dataset",
            "description": "Test",
        },
    )
    assert response.status_code == 401


def test_csrf_missing_bearer_prefix_fails(xss_client: TestClient):
    """Test that tokens without Bearer prefix are rejected."""
    headers = {"Authorization": "some-token-12345"}

    response = xss_client.post(
        "/api/datasets",
        headers=headers,
        json={
            "name": "Test Dataset",
            "description": "Test",
        },
    )
    assert response.status_code == 401


def test_csrf_approval_list_requires_auth(xss_client: TestClient):
    """Test that listing approvals requires authentication."""
    response = xss_client.get("/api/approvals")
    assert response.status_code == 401


def test_csrf_approval_get_requires_auth(xss_client: TestClient, xss_session: Session):
    """Test that getting a single approval requires authentication."""
    approval = Approval(
        approval_id="approval_csrf_test_2",
        tool="test_tool",
        inputs={"action": "test"},
        status=ApprovalStatus.PENDING,
    )
    xss_session.add(approval)
    xss_session.commit()

    response = xss_client.get("/api/approvals/approval_csrf_test_2")
    assert response.status_code == 401


def test_csrf_trace_list_requires_auth(xss_client: TestClient):
    """Test that trace listing requires authentication."""
    response = xss_client.get("/api/traces")
    # Trace listing now requires authentication for security
    assert response.status_code == 401
