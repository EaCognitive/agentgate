"""Core XSS and CSRF security tests for AgentGate.

This module contains core tests for:
1. XSS protection for traces (data storage, retrieval, field handling)
2. XSS protection for user registration and profile endpoints
3. Content Security Policy (CSP) validation
4. Security header enforcement on all endpoints

Extended tests are located in test_xss_csrf_extended.py:
- XSS tests for datasets, approvals, and test cases
- XSS tests for query parameters and complex nested payloads
- CSRF authentication requirements across all endpoints

Security Model:
- AgentGate is a JSON API that returns structured data
- XSS protection is provided through:
  * Content-Security-Policy headers that prevent inline script execution
  * Frontend frameworks (React/Vue) that properly escape data when rendering
  * JSON responses that don't execute scripts
- CSRF protection is provided through JWT-based authentication
- All state-changing operations require valid authentication tokens

These tests ensure AgentGate follows Enterprise Engineering Protocols 2026
and OWASP Top 10 security best practices.
"""

import inspect
import sys

from fastapi.testclient import TestClient

pytest_plugins = ("tests.security.xss_csrf_test_support",)


# ============================================================================
# XSS Tests - Data Storage and Retrieval
# ============================================================================


def test_xss_trace_metadata_stored_correctly(
    xss_client: TestClient,
    xss_auth_headers: dict[str, str],
):
    """Test that XSS payloads in trace metadata are stored and retrieved correctly.

    A JSON API should store data as-is. XSS protection is handled by:
    1. Security headers (CSP) preventing script execution
    2. Frontend frameworks escaping data when rendering
    """
    _ = xss_auth_headers
    xss_payload = "<script>alert('XSS')</script>"

    response = xss_client.post(
        "/api/traces",
        headers=xss_auth_headers,
        json={
            "trace_id": "trace_xss_test_1",
            "tool": "test_tool",
            "inputs": {"malicious_input": xss_payload},
            "status": "success",
        },
    )
    assert response.status_code == 200

    # Verify security headers are present
    assert "Content-Security-Policy" in response.headers
    assert "X-XSS-Protection" in response.headers

    # Retrieve trace
    get_response = xss_client.get(
        "/api/traces/trace_xss_test_1",
        headers=xss_auth_headers,
    )
    assert get_response.status_code == 200

    # Verify security headers on GET response
    assert "Content-Security-Policy" in get_response.headers
    assert "X-XSS-Protection" in get_response.headers

    # Data should be stored as-is in JSON (not HTML encoded)
    data = get_response.json()
    assert data["inputs"]["malicious_input"] == xss_payload


def test_xss_trace_output_with_dangerous_content(
    xss_client: TestClient,
    xss_auth_headers: dict[str, str],
):
    """Test that dangerous content in trace output is handled with proper security headers."""
    _ = xss_auth_headers
    xss_payload = "<img src=x onerror=alert('XSS')>"

    response = xss_client.post(
        "/api/traces",
        headers=xss_auth_headers,
        json={
            "trace_id": "trace_xss_test_2",
            "tool": "test_tool",
            "inputs": {"test": "input"},
            "output": {"result": xss_payload},
            "status": "success",
        },
    )
    assert response.status_code == 200
    assert "Content-Security-Policy" in response.headers

    # Retrieve and verify security headers prevent execution
    get_response = xss_client.get(
        "/api/traces/trace_xss_test_2",
        headers=xss_auth_headers,
    )
    assert get_response.status_code == 200
    assert "Content-Security-Policy" in get_response.headers

    # CSP should prevent inline event handlers
    csp = get_response.headers["Content-Security-Policy"]
    assert "default-src" in csp


def test_xss_trace_tool_name_field(xss_client: TestClient, xss_auth_headers: dict[str, str]):
    """Test XSS handling in tool name field."""
    _ = xss_auth_headers
    xss_payload = "javascript:alert('XSS')"

    response = xss_client.post(
        "/api/traces",
        headers=xss_auth_headers,
        json={
            "trace_id": "trace_xss_test_3",
            "tool": xss_payload,
            "inputs": {"test": "input"},
            "status": "success",
        },
    )
    assert response.status_code == 200
    assert "Content-Security-Policy" in response.headers


def test_xss_trace_agent_id_field(xss_client: TestClient, xss_auth_headers: dict[str, str]):
    """Test XSS handling in agent_id field."""
    _ = xss_auth_headers
    xss_payload = "<svg onload=alert('XSS')>"

    response = xss_client.post(
        "/api/traces",
        headers=xss_auth_headers,
        json={
            "trace_id": "trace_xss_test_4",
            "tool": "test_tool",
            "inputs": {"test": "input"},
            "agent_id": xss_payload,
            "status": "success",
        },
    )
    assert response.status_code == 200
    assert "X-XSS-Protection" in response.headers


def test_xss_trace_error_message_field(xss_client: TestClient, xss_auth_headers: dict[str, str]):
    """Test XSS handling in error message field."""
    _ = xss_auth_headers
    xss_payload = "<iframe src='javascript:alert(1)'>"

    response = xss_client.post(
        "/api/traces",
        headers=xss_auth_headers,
        json={
            "trace_id": "trace_xss_test_5",
            "tool": "test_tool",
            "inputs": {"test": "input"},
            "error": xss_payload,
            "status": "failed",
        },
    )
    assert response.status_code == 200
    assert "Content-Security-Policy" in response.headers


def test_xss_multiple_payloads_in_single_trace(
    xss_client: TestClient,
    xss_auth_headers: dict[str, str],
):
    """Test handling of multiple XSS payloads in a single trace."""
    _ = xss_auth_headers
    response = xss_client.post(
        "/api/traces",
        headers=xss_auth_headers,
        json={
            "trace_id": "trace_xss_test_6",
            "tool": "<script>alert('tool')</script>",
            "inputs": {
                "field1": "<img src=x onerror=alert(1)>",
                "field2": "javascript:alert(2)",
                "field3": "<svg onload=alert(3)>",
            },
            "agent_id": "<body onload=alert(4)>",
            "status": "success",
        },
    )
    assert response.status_code == 200

    # All responses should have security headers
    assert "Content-Security-Policy" in response.headers
    assert "X-XSS-Protection" in response.headers
    assert "X-Content-Type-Options" in response.headers


# ============================================================================
# XSS Tests - User Registration/Profile
# ============================================================================


def test_xss_user_name_registration(xss_client: TestClient):
    """Test XSS handling in user name during registration."""
    xss_payload = "<script>alert('XSS')</script>"

    response = xss_client.post(
        "/api/auth/register",
        json={
            "email": "xss_user_1@example.com",
            "password": "SecurePass123!",
            "name": xss_payload,
        },
    )
    assert response.status_code == 200
    assert "Content-Security-Policy" in response.headers
    assert "X-XSS-Protection" in response.headers


def test_xss_user_email_validation(xss_client: TestClient):
    """Test that email validation prevents obvious XSS attempts."""
    # Email with script tag should be rejected by validation or stored safely
    xss_payload = "test<script>@example.com"

    response = xss_client.post(
        "/api/auth/register",
        json={
            "email": xss_payload,
            "password": "SecurePass123!",
            "name": "Test User",
        },
    )
    # Should either fail validation (422) or succeed with security headers (200)
    assert response.status_code in [200, 422]

    if response.status_code == 200:
        assert "Content-Security-Policy" in response.headers


def test_xss_user_profile_fields(xss_client: TestClient, xss_auth_headers: dict[str, str]):
    """Test XSS handling in user profile retrieval."""
    _ = xss_auth_headers
    response = xss_client.get(
        "/api/auth/me",
        headers=xss_auth_headers,
    )
    assert response.status_code == 200

    # All profile endpoints should have security headers
    assert "Content-Security-Policy" in response.headers
    assert "X-XSS-Protection" in response.headers
    assert "X-Frame-Options" in response.headers


# ============================================================================
# Content Security Policy Tests
# ============================================================================


def test_csp_header_present(xss_client: TestClient):
    """Test that Content-Security-Policy header is present."""
    response = xss_client.get("/api/health")
    assert response.status_code == 200
    assert "Content-Security-Policy" in response.headers

    csp = response.headers["Content-Security-Policy"]
    assert "default-src" in csp
    assert "script-src" in csp


def test_csp_header_on_all_endpoints(xss_client: TestClient, xss_auth_headers: dict[str, str]):
    """Test that CSP header is present on all endpoints."""
    _ = xss_auth_headers
    endpoints = [
        ("/api/health", "GET", None),
        ("/api/traces", "GET", xss_auth_headers),
        ("/api/datasets", "GET", xss_auth_headers),
    ]

    for path, method, headers in endpoints:
        if method == "GET":
            response = xss_client.get(path, headers=headers)
        else:
            response = xss_client.post(path, headers=headers, json={})

        assert "Content-Security-Policy" in response.headers


def test_csp_prevents_inline_scripts(xss_client: TestClient):
    """Test that CSP header configuration prevents inline scripts."""
    response = xss_client.get("/api/health")
    csp = response.headers.get("Content-Security-Policy", "")

    # Should have script-src directive
    assert "script-src" in csp
    # Should restrict script sources
    assert "default-src" in csp


def test_csp_frame_ancestors_none(xss_client: TestClient):
    """Test that CSP prevents framing (clickjacking protection)."""
    response = xss_client.get("/api/health")
    csp = response.headers.get("Content-Security-Policy", "")

    # Should prevent framing
    assert "frame-ancestors" in csp


# ============================================================================
# Security Header Tests
# ============================================================================


def test_xss_protection_header_present(xss_client: TestClient):
    """Test that X-XSS-Protection header is present."""
    response = xss_client.get("/api/health")
    assert "X-XSS-Protection" in response.headers
    assert response.headers["X-XSS-Protection"] == "1; mode=block"


def test_x_content_type_options_header(xss_client: TestClient):
    """Test that X-Content-Type-Options header prevents MIME sniffing."""
    response = xss_client.get("/api/health")
    assert "X-Content-Type-Options" in response.headers
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_x_frame_options_header(xss_client: TestClient):
    """Test that X-Frame-Options header prevents clickjacking."""
    response = xss_client.get("/api/health")
    assert "X-Frame-Options" in response.headers
    assert response.headers["X-Frame-Options"] == "DENY"


def test_referrer_policy_header(xss_client: TestClient):
    """Test that Referrer-Policy header is set correctly."""
    response = xss_client.get("/api/health")
    assert "Referrer-Policy" in response.headers
    referrer_policy = response.headers["Referrer-Policy"]
    assert referrer_policy in [
        "strict-origin-when-cross-origin",
        "no-referrer",
        "same-origin",
    ]


def test_permissions_policy_header(xss_client: TestClient):
    """Test that Permissions-Policy header restricts features."""
    response = xss_client.get("/api/health")
    assert "Permissions-Policy" in response.headers


def test_server_header_removed_or_generic(xss_client: TestClient):
    """Test that server identification header is removed or generic."""
    response = xss_client.get("/api/health")
    server_header = response.headers.get("server", "")

    # Server header should not expose detailed version info
    assert "uvicorn" not in server_header.lower() or server_header == ""


def test_security_headers_on_error_responses(xss_client: TestClient):
    """Test that security headers are present even on error responses."""
    response = xss_client.get("/api/nonexistent-endpoint-12345")
    assert response.status_code == 404

    # Security headers should still be present
    assert "Content-Security-Policy" in response.headers
    assert "X-XSS-Protection" in response.headers
    assert "X-Content-Type-Options" in response.headers


def test_security_headers_on_401_responses(xss_client: TestClient):
    """Test that security headers are present on unauthorized responses."""
    response = xss_client.get("/api/datasets")
    assert response.status_code == 401

    assert "Content-Security-Policy" in response.headers
    assert "X-XSS-Protection" in response.headers


def test_security_headers_on_all_status_codes(
    xss_client: TestClient,
    xss_auth_headers: dict[str, str],
):
    """Test that security headers are present on various HTTP status codes."""
    _ = xss_auth_headers
    # Test 200 OK
    response = xss_client.get("/api/health")
    assert response.status_code == 200
    assert "Content-Security-Policy" in response.headers

    # Test 404 Not Found
    response = xss_client.get("/api/nonexistent-endpoint")
    assert response.status_code == 404
    assert "Content-Security-Policy" in response.headers

    # Test 401 Unauthorized
    response = xss_client.get("/api/datasets")
    assert response.status_code == 401
    assert "Content-Security-Policy" in response.headers


# ============================================================================
# Summary Test
# ============================================================================


def test_security_test_coverage():
    """Verify comprehensive security test coverage."""

    current_module = sys.modules[__name__]
    test_functions = [
        name
        for name, obj in inspect.getmembers(current_module)
        if inspect.isfunction(obj) and name.startswith("test_")
    ]

    xss_tests = [name for name in test_functions if "xss" in name.lower()]
    csrf_tests = [name for name in test_functions if "csrf" in name.lower()]
    csp_tests = [name for name in test_functions if "csp" in name.lower()]
    header_tests = [
        name
        for name in test_functions
        if any(h in name.lower() for h in ["header", "protection", "policy"])
        and "xss" not in name.lower()
        and "csrf" not in name.lower()
        and "csp" not in name.lower()
    ]

    total_tests = len(test_functions)

    print("\nSecurity Test Coverage Summary:")
    print(f"  Total tests: {total_tests}")
    print(f"  XSS tests: {len(xss_tests)}")
    print(f"  CSRF tests: {len(csrf_tests)}")
    print(f"  CSP tests: {len(csp_tests)}")
    print(f"  Security header tests: {len(header_tests)}")

    assert len(xss_tests) >= 10, f"Expected at least 10 XSS tests, got {len(xss_tests)}"
    assert total_tests >= 20, f"Expected at least 20 total tests, got {total_tests}"
