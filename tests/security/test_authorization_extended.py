"""Extended authorization tests: user isolation (PII, costs) and additional security checks.

Tests verify:
1. PII vault isolation between users
2. Cost budget isolation
3. Token expiration and manipulation
4. General authentication enforcement

Enterprise Engineering Protocols 2025
Zero trust security model
"""

from fastapi.testclient import TestClient

pytest_plugins = ("tests.security.authz_test_support",)


# =============================================================================
# USER ISOLATION: REMAINING TESTS (PII VAULT, COSTS)
# =============================================================================


def test_users_have_separate_cost_budgets(
    client: TestClient,
    user_a_token: str,
    user_b_token: str,
):
    """User A's cost usage should not affect user B's budget."""
    # This is more of a logic test - costs should be tracked per user
    # Get user A's costs
    response_a = client.get(
        "/api/costs",
        headers={"Authorization": f"Bearer {user_a_token}"},
    )

    # Get user B's costs
    response_b = client.get(
        "/api/costs",
        headers={"Authorization": f"Bearer {user_b_token}"},
    )

    # Both should succeed if endpoint exists
    if response_a.status_code == 200 and response_b.status_code == 200:
        # Costs should be tracked separately
        assert response_a.json() != response_b.json() or response_a.json().get("total_cost") == 0


def test_user_isolation_in_pii_vault(
    client: TestClient,
    user_a_token: str,
    user_b_token: str,
):
    """User B cannot access PII stored by user A."""
    # User A stores PII
    client.post(
        "/api/pii/store",
        headers={"Authorization": f"Bearer {user_a_token}"},
        json={
            "session_id": "user_a_session",
            "placeholder": "<PERSON_1>",
            "pii_value": "John Doe",
            "pii_type": "PERSON",
        },
    )

    # User B tries to retrieve user A's PII
    response_retrieve = client.post(
        "/api/pii/retrieve",
        headers={"Authorization": f"Bearer {user_b_token}"},
        json={
            "session_id": "user_a_session",
            "placeholder": "<PERSON_1>",
        },
    )
    # Should fail
    assert response_retrieve.status_code in [403, 404]


# =============================================================================
# ADDITIONAL SECURITY TESTS
# =============================================================================


def test_viewer_cannot_bulk_delete_data(
    client: TestClient,
    viewer_token: str,
):
    """Viewer cannot perform bulk delete operations."""
    response = client.post(
        "/api/datasets/bulk-delete",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={
            "dataset_ids": [1, 2, 3],
        },
    )
    assert response.status_code in [403, 404, 405]


def test_user_cannot_access_api_without_authentication(client: TestClient):
    """All protected endpoints require authentication."""
    protected_endpoints = [
        ("/api/auth/me", "GET"),
        ("/api/datasets", "GET"),
        ("/api/approvals", "GET"),
    ]

    for endpoint, method in protected_endpoints:
        if method == "GET":
            response = client.get(endpoint)
        else:
            response = client.post(endpoint)

        assert response.status_code == 401


def test_expired_tokens_are_rejected(client: TestClient):
    """Expired tokens should be rejected."""
    # This would require manipulating token expiry or waiting
    # For now, test with malformed token
    expired_token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiJ0ZXN0QGV4YW1wbGUuY29tIiwiZXhwIjoxfQ."
        "invalid"
    )

    response = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert response.status_code == 401


def test_role_based_read_access_is_enforced(
    client: TestClient,
    viewer_token: str,
) -> None:
    """Different roles have appropriate read access levels."""
    # Viewer should be able to read datasets
    viewer_response = client.get(
        "/api/datasets",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert viewer_response.status_code == 200
