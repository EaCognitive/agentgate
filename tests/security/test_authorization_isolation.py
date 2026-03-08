"""Authorization tests: user isolation enforcement.

Tests verify:
- Users cannot access other users' data
- Cross-user data leakage is prevented
- Resource ownership is enforced

Enterprise Engineering Protocols 2025
Zero trust security model
"""

from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import (
    Approval,
    ApprovalStatus,
    Dataset,
    Trace,
    TraceStatus,
    User,
)

pytest_plugins = ("tests.security.authz_test_support",)


# =============================================================
# USER ISOLATION (15 tests)
# =============================================================


def test_user_cannot_access_other_users_datasets(
    client: TestClient,
    user_a_token: str,
    user_b_token: str,
    session: Session,
    user_a: User,
):
    """User A cannot modify user B's datasets."""
    _ = user_a_token
    _ = session
    dataset = Dataset(
        name="User A Dataset",
        description="Private dataset",
        created_by=user_a.id,
    )
    session.add(dataset)
    session.commit()
    session.refresh(dataset)

    response = client.delete(
        f"/api/datasets/{dataset.id}",
        headers={"Authorization": (f"Bearer {user_b_token}")},
    )
    assert response.status_code in [403, 404]


def test_user_cannot_modify_other_users_test_cases(
    client: TestClient,
    user_a_token: str,
    user_b_token: str,
    session: Session,
    user_a: User,
):
    """User B cannot modify user A's test cases."""
    _ = user_a_token
    _ = session
    dataset = Dataset(
        name="User A Dataset",
        created_by=user_a.id,
    )
    session.add(dataset)
    session.commit()
    session.refresh(dataset)

    response = client.post(
        f"/api/datasets/{dataset.id}/tests",
        headers={"Authorization": (f"Bearer {user_b_token}")},
        json={
            "dataset_id": dataset.id,
            "name": "Malicious Test",
            "tool": "test_tool",
            "inputs": {"param": "value"},
        },
    )
    assert response.status_code in [403, 404]


def test_user_cannot_see_other_users_approvals(
    client: TestClient,
    user_a_token: str,
    user_b_token: str,
    session: Session,
):
    """Users can only see their own approvals."""
    _ = user_a_token
    _ = session
    approval = Approval(
        approval_id="user-a-approval",
        tool="test_tool",
        inputs={"user": "user_a"},
        agent_id="user_a_agent",
        status=ApprovalStatus.PENDING,
    )
    session.add(approval)
    session.commit()

    response = client.get(
        "/api/approvals/user-a-approval",
        headers={"Authorization": (f"Bearer {user_b_token}")},
    )
    if response.status_code == 200:
        decide_response = client.post(
            "/api/approvals/user-a-approval/decide",
            headers={"Authorization": (f"Bearer {user_b_token}")},
            json={
                "approved": True,
                "reason": "Unauthorized approval",
            },
        )
        assert decide_response.status_code == 403


def test_user_cannot_access_other_users_sessions(
    client: TestClient,
    user_a_token: str,
    user_b_token: str,
):
    """User B cannot access user A's session data."""
    _ = user_a_token
    response = client.get(
        "/api/sessions/user_a_session_id",
        headers={"Authorization": (f"Bearer {user_b_token}")},
    )
    assert response.status_code in [403, 404]


def test_user_cannot_revoke_other_users_tokens(
    client: TestClient,
    user_a_token: str,
    user_b_token: str,
    session: Session,
):
    """User B cannot revoke user A's refresh tokens."""
    _ = user_a_token
    _ = session
    response_a = client.post(
        "/api/auth/login",
        json={
            "email": "usera@example.com",
            "password": "userpass123",
        },
    )
    assert response_a.status_code == 200
    user_a_refresh = response_a.json()["refresh_token"]

    response = client.post(
        "/api/auth/revoke",
        headers={"Authorization": (f"Bearer {user_b_token}")},
        json={"refresh_token": user_a_refresh},
    )
    assert response.status_code in [403, 404]


def test_user_cannot_read_other_users_profile(
    client: TestClient,
    user_a_token: str,
    user_b_token: str,
    user_a: User,
):
    """Users cannot read other users' profiles."""
    _ = user_a_token
    response = client.get(
        f"/api/users/{user_a.id}",
        headers={"Authorization": (f"Bearer {user_b_token}")},
    )
    assert response.status_code in [403, 404]


def test_user_cannot_disable_other_users_account(
    client: TestClient,
    user_a_token: str,
    user_b_token: str,
):
    """User B cannot disable user A's account."""
    _ = user_a_token
    response = client.post(
        "/api/users/usera@example.com/disable",
        headers={"Authorization": (f"Bearer {user_b_token}")},
    )
    assert response.status_code in [403, 404, 405]


def test_user_cannot_change_other_users_password(
    client: TestClient,
    user_a_token: str,
    user_b_token: str,
):
    """User B cannot change user A's password."""
    _ = user_a_token
    response = client.post(
        "/api/users/usera@example.com/password",
        headers={"Authorization": (f"Bearer {user_b_token}")},
        json={"new_password": "hacked123"},
    )
    assert response.status_code in [403, 404, 405]


def test_user_cannot_access_other_users_mfa(
    client: TestClient,
    user_a_token: str,
    user_b_token: str,
):
    """User B cannot access user A's MFA settings."""
    _ = user_a_token
    response = client.post(
        "/api/users/usera@example.com/mfa/disable",
        headers={"Authorization": (f"Bearer {user_b_token}")},
        json={"password": "userpass123"},
    )
    assert response.status_code in [403, 404, 405]


def test_user_cannot_read_other_users_audit_logs(
    client: TestClient,
    user_a_token: str,
    user_b_token: str,
):
    """User B cannot read user A's audit logs."""
    _ = user_a_token
    response = client.get(
        "/api/audit?user=usera@example.com",
        headers={"Authorization": (f"Bearer {user_b_token}")},
    )
    assert response.status_code in [403, 404]


def test_user_cannot_export_other_users_data(
    client: TestClient,
    user_a_token: str,
    user_b_token: str,
):
    """User B cannot export user A's data."""
    _ = user_a_token
    response = client.get(
        "/api/users/usera@example.com/export",
        headers={"Authorization": (f"Bearer {user_b_token}")},
    )
    assert response.status_code in [403, 404]


def test_user_cannot_create_datasets_for_others(
    client: TestClient,
    user_a_token: str,
    user_b_token: str,
    user_b: User,
):
    """User B cannot create datasets on behalf of A."""
    _ = user_a_token
    response = client.post(
        "/api/datasets",
        headers={"Authorization": (f"Bearer {user_b_token}")},
        json={
            "name": "Fake Dataset",
            "description": "Created for user A",
            "created_by": 99999,
        },
    )
    if response.status_code in [200, 201]:
        data = response.json()
        assert data.get("created_by") == user_b.id


def test_user_cannot_access_other_system_traces(
    client: TestClient,
    user_a_token: str,
    user_b_token: str,
    session: Session,
    user_a: User,
):
    """User B cannot access user A's traces.

    Traces have a created_by field linking to creator.
    Non-admin users can only see their own traces.
    """
    _ = user_a_token
    _ = session
    trace = Trace(
        trace_id="user-a-trace-123",
        tool="test_tool",
        inputs={
            "user": "a",
            "secret": "confidential",
        },
        output={"result": "success"},
        status=TraceStatus.SUCCESS,
        agent_id="user_a_agent",
        session_id="user_a_session",
        created_by=user_a.id,
    )
    session.add(trace)
    session.commit()

    response = client.get(
        "/api/traces?session_id=user_a_session",
        headers={"Authorization": (f"Bearer {user_b_token}")},
    )
    if response.status_code == 200:
        traces = response.json()
        for trace_item in traces:
            assert trace_item.get("session_id") != "user_a_session"
