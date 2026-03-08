"""Tests for policy activate and deactivate endpoints.

Covers POST /api/policies/{db_id}/activate and
POST /api/policies/{db_id}/deactivate, verifying success paths,
404 handling, mutual-exclusion invariant, and response shape.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import true
from sqlmodel import Session, select

from server.main import app
from server.models import User, get_session
from server.models.security_policy_schemas import SecurityPolicy
from server.routers.auth import create_access_token
from server.routers.auth_utils import (
    _get_password_hash_sync as get_password_hash,
)
from tests.sqlite_test_helpers import client_with_session_override, in_memory_session

# ------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------

_ADMIN_EMAIL = "policy-activation-admin@test.com"
_ADMIN_PASSWORD = "AdminPass123!"
_HMAC_PLACEHOLDER = "dev-only-hmac-placeholder"

_POLICY_JSON_ALPHA: dict[str, Any] = {
    "policy_set_id": "policy-alpha",
    "version": "1.0",
    "description": "Alpha test policy",
    "default_effect": "allow",
    "rules": [],
}
_POLICY_JSON_BETA: dict[str, Any] = {
    "policy_set_id": "policy-beta",
    "version": "1.0",
    "description": "Beta test policy",
    "default_effect": "deny",
    "rules": [],
}

_POLICY_SET_RESPONSE_FIELDS = frozenset(
    {
        "policy_set_id",
        "version",
        "description",
        "default_effect",
        "rule_count",
        "loaded",
        "db_id",
        "origin",
        "locked",
        "is_active",
    }
)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _compute_test_hmac(policy_json: dict[str, Any]) -> str:
    """Compute HMAC-SHA256 matching the router's dev-mode signature.

    Args:
        policy_json: Policy dict to sign.

    Returns:
        Hexadecimal HMAC-SHA256 digest.
    """
    canonical = json.dumps(policy_json, sort_keys=True)
    return hmac.new(
        _HMAC_PLACEHOLDER.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _utc_now() -> datetime:
    """Return current UTC time as a naive datetime."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _make_security_policy(
    policy_json: dict[str, Any],
    *,
    created_by_user_id: int | None = None,
    is_active: bool = False,
) -> SecurityPolicy:
    """Construct an unpersisted SecurityPolicy ORM object.

    Args:
        policy_json: Serialisable policy dict.
        created_by_user_id: Optional owner user ID.
        is_active: Initial activation state.

    Returns:
        Unpersisted SecurityPolicy instance.
    """
    return SecurityPolicy(
        policy_id=policy_json["policy_set_id"],
        version=1,
        policy_json=policy_json,
        origin="manual",
        created_by_user_id=created_by_user_id,
        hmac_signature=_compute_test_hmac(policy_json),
        locked=False,
        is_active=is_active,
    )


def _make_admin_headers(admin_user: User) -> dict[str, str]:
    """Build Bearer token headers for an admin user.

    Args:
        admin_user: Persisted admin User instance.

    Returns:
        HTTP Authorization header dict.
    """
    token = create_access_token(
        data={
            "sub": admin_user.email,
            "role": admin_user.role,
            "session_assurance": "A3",
        },
        expires_delta=timedelta(minutes=15),
    )
    return {"Authorization": f"Bearer {token}"}


def _make_viewer_headers(viewer_user: User) -> dict[str, str]:
    """Build Bearer token headers for a non-admin user.

    Args:
        viewer_user: Persisted non-admin User instance.

    Returns:
        HTTP Authorization header dict.
    """
    token = create_access_token(
        data={
            "sub": viewer_user.email,
            "role": viewer_user.role,
            "session_assurance": "A3",
        },
        expires_delta=timedelta(minutes=15),
    )
    return {"Authorization": f"Bearer {token}"}


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------


@pytest.fixture(name="session")
def session_fixture():
    """Create isolated in-memory SQLModel session."""
    yield from in_memory_session()


@pytest.fixture(name="client")
def client_fixture(session: Session) -> TestClient:
    """Create TestClient with DB dependency override."""
    yield from client_with_session_override(app, get_session, session)


@pytest.fixture(name="admin_user")
def admin_user_fixture(session: Session) -> User:
    """Create and persist an admin user."""
    user = User(
        email=_ADMIN_EMAIL,
        name="Policy Activation Admin",
        hashed_password=get_password_hash(_ADMIN_PASSWORD),
        role="admin",
        is_active=True,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@pytest.fixture(name="admin_headers")
def admin_headers_fixture(admin_user: User) -> dict[str, str]:
    """Bearer token headers for the admin user."""
    return _make_admin_headers(admin_user)


# ------------------------------------------------------------------
# Activate endpoint tests
# ------------------------------------------------------------------


def test_activate_returns_200_with_is_active_true(
    client: TestClient,
    session: Session,
    admin_user: User,
    admin_headers: dict[str, str],
) -> None:
    """Activating a policy returns HTTP 200 and is_active=True."""
    policy = _make_security_policy(
        _POLICY_JSON_ALPHA,
        created_by_user_id=admin_user.id,
    )
    session.add(policy)
    session.commit()
    session.refresh(policy)

    response = client.post(
        f"/api/policies/{policy.id}/activate",
        headers=admin_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["is_active"] is True
    assert body["db_id"] == policy.id
    assert body["policy_set_id"] == "policy-alpha"


def test_activate_response_includes_all_required_fields(
    client: TestClient,
    session: Session,
    admin_user: User,
    admin_headers: dict[str, str],
) -> None:
    """Activate response must include all PolicySetResponse fields."""
    policy = _make_security_policy(
        _POLICY_JSON_BETA,
        created_by_user_id=admin_user.id,
    )
    session.add(policy)
    session.commit()
    session.refresh(policy)

    response = client.post(
        f"/api/policies/{policy.id}/activate",
        headers=admin_headers,
    )

    assert response.status_code == 200
    assert _POLICY_SET_RESPONSE_FIELDS.issubset(response.json().keys())


def test_activate_deactivates_all_other_active_policies(
    client: TestClient,
    session: Session,
    admin_user: User,
    admin_headers: dict[str, str],
) -> None:
    """Activating a policy deactivates all other active policies.

    Enforces the at-most-one-active invariant.
    """
    previously_active = _make_security_policy(
        _POLICY_JSON_ALPHA,
        created_by_user_id=admin_user.id,
        is_active=True,
    )
    previously_active.activated_at = _utc_now()
    previously_active.activated_by_user_id = admin_user.id

    target_policy = _make_security_policy(
        _POLICY_JSON_BETA,
        created_by_user_id=admin_user.id,
    )

    session.add(previously_active)
    session.add(target_policy)
    session.commit()
    session.refresh(previously_active)
    session.refresh(target_policy)

    response = client.post(
        f"/api/policies/{target_policy.id}/activate",
        headers=admin_headers,
    )
    assert response.status_code == 200
    assert response.json()["is_active"] is True

    session.expire_all()
    prev_record = session.get(SecurityPolicy, previously_active.id)

    assert prev_record is not None
    assert prev_record.is_active is False
    assert prev_record.activated_at is None
    assert prev_record.activated_by_user_id is None


def test_activate_returns_404_when_policy_not_found(
    client: TestClient,
    admin_headers: dict[str, str],
) -> None:
    """Activating a non-existent policy returns HTTP 404."""
    response = client.post(
        "/api/policies/99999/activate",
        headers=admin_headers,
    )

    assert response.status_code == 404
    assert "99999" in response.json()["detail"]


def test_activate_rejects_non_admin_with_403(
    client: TestClient,
    session: Session,
    admin_user: User,
) -> None:
    """Non-admin users receive HTTP 403 on activate."""
    viewer = User(
        email="viewer-activate@test.com",
        name="Viewer User",
        hashed_password=get_password_hash("ViewerPass123!"),
        role="viewer",
        is_active=True,
    )
    session.add(viewer)
    session.commit()
    session.refresh(viewer)

    policy = _make_security_policy(
        _POLICY_JSON_ALPHA,
        created_by_user_id=admin_user.id,
    )
    session.add(policy)
    session.commit()
    session.refresh(policy)

    response = client.post(
        f"/api/policies/{policy.id}/activate",
        headers=_make_viewer_headers(viewer),
    )

    assert response.status_code == 403


def test_activate_rejects_unauthenticated_request(
    client: TestClient,
    session: Session,
    admin_user: User,
) -> None:
    """Activate endpoint rejects unauthenticated requests."""
    policy = _make_security_policy(
        _POLICY_JSON_ALPHA,
        created_by_user_id=admin_user.id,
    )
    session.add(policy)
    session.commit()
    session.refresh(policy)

    response = client.post(
        f"/api/policies/{policy.id}/activate",
    )

    assert response.status_code == 401


# ------------------------------------------------------------------
# Deactivate endpoint tests
# ------------------------------------------------------------------


def test_deactivate_returns_200_with_is_active_false(
    client: TestClient,
    session: Session,
    admin_user: User,
    admin_headers: dict[str, str],
) -> None:
    """Deactivating a policy returns HTTP 200 and is_active=False."""
    policy = _make_security_policy(
        _POLICY_JSON_ALPHA,
        created_by_user_id=admin_user.id,
        is_active=True,
    )
    policy.activated_at = _utc_now()
    policy.activated_by_user_id = admin_user.id

    session.add(policy)
    session.commit()
    session.refresh(policy)

    response = client.post(
        f"/api/policies/{policy.id}/deactivate",
        headers=admin_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["is_active"] is False
    assert body["db_id"] == policy.id


def test_deactivate_response_includes_all_required_fields(
    client: TestClient,
    session: Session,
    admin_user: User,
    admin_headers: dict[str, str],
) -> None:
    """Deactivate response includes all PolicySetResponse fields."""
    policy = _make_security_policy(
        _POLICY_JSON_ALPHA,
        created_by_user_id=admin_user.id,
        is_active=True,
    )
    policy.activated_at = _utc_now()
    policy.activated_by_user_id = admin_user.id

    session.add(policy)
    session.commit()
    session.refresh(policy)

    response = client.post(
        f"/api/policies/{policy.id}/deactivate",
        headers=admin_headers,
    )

    assert response.status_code == 200
    assert _POLICY_SET_RESPONSE_FIELDS.issubset(response.json().keys())


def test_deactivate_already_inactive_policy_succeeds(
    client: TestClient,
    session: Session,
    admin_user: User,
    admin_headers: dict[str, str],
) -> None:
    """Deactivating an already-inactive policy succeeds idempotently."""
    policy = _make_security_policy(
        _POLICY_JSON_ALPHA,
        created_by_user_id=admin_user.id,
        is_active=False,
    )
    session.add(policy)
    session.commit()
    session.refresh(policy)

    response = client.post(
        f"/api/policies/{policy.id}/deactivate",
        headers=admin_headers,
    )

    assert response.status_code == 200
    assert response.json()["is_active"] is False


def test_deactivate_returns_404_when_policy_not_found(
    client: TestClient,
    admin_headers: dict[str, str],
) -> None:
    """Deactivating a non-existent policy returns HTTP 404."""
    response = client.post(
        "/api/policies/99999/deactivate",
        headers=admin_headers,
    )

    assert response.status_code == 404
    assert "99999" in response.json()["detail"]


def test_deactivate_rejects_non_admin_with_403(
    client: TestClient,
    session: Session,
    admin_user: User,
) -> None:
    """Non-admin users receive HTTP 403 on deactivate."""
    viewer = User(
        email="viewer-deactivate@test.com",
        name="Viewer User",
        hashed_password=get_password_hash("ViewerPass123!"),
        role="viewer",
        is_active=True,
    )
    session.add(viewer)
    session.commit()
    session.refresh(viewer)

    policy = _make_security_policy(
        _POLICY_JSON_BETA,
        created_by_user_id=admin_user.id,
        is_active=True,
    )
    policy.activated_at = _utc_now()
    policy.activated_by_user_id = admin_user.id

    session.add(policy)
    session.commit()
    session.refresh(policy)

    response = client.post(
        f"/api/policies/{policy.id}/deactivate",
        headers=_make_viewer_headers(viewer),
    )

    assert response.status_code == 403


def test_deactivate_rejects_unauthenticated_request(
    client: TestClient,
    session: Session,
    admin_user: User,
) -> None:
    """Deactivate endpoint rejects unauthenticated requests."""
    policy = _make_security_policy(
        _POLICY_JSON_ALPHA,
        created_by_user_id=admin_user.id,
        is_active=True,
    )
    session.add(policy)
    session.commit()
    session.refresh(policy)

    response = client.post(
        f"/api/policies/{policy.id}/deactivate",
    )

    assert response.status_code == 401


# ------------------------------------------------------------------
# Round-trip and invariant tests
# ------------------------------------------------------------------


def test_activate_then_deactivate_round_trip(
    client: TestClient,
    session: Session,
    admin_user: User,
    admin_headers: dict[str, str],
) -> None:
    """Activate then deactivate leaves is_active=False."""
    policy = _make_security_policy(
        _POLICY_JSON_ALPHA,
        created_by_user_id=admin_user.id,
    )
    session.add(policy)
    session.commit()
    session.refresh(policy)

    activate_resp = client.post(
        f"/api/policies/{policy.id}/activate",
        headers=admin_headers,
    )
    assert activate_resp.status_code == 200
    assert activate_resp.json()["is_active"] is True

    deactivate_resp = client.post(
        f"/api/policies/{policy.id}/deactivate",
        headers=admin_headers,
    )
    assert deactivate_resp.status_code == 200
    assert deactivate_resp.json()["is_active"] is False


def test_activating_second_policy_leaves_exactly_one_active(
    client: TestClient,
    session: Session,
    admin_user: User,
    admin_headers: dict[str, str],
) -> None:
    """After activating a second policy, exactly one is active."""
    policy_a = _make_security_policy(
        _POLICY_JSON_ALPHA,
        created_by_user_id=admin_user.id,
    )
    policy_b = _make_security_policy(
        _POLICY_JSON_BETA,
        created_by_user_id=admin_user.id,
    )
    session.add(policy_a)
    session.add(policy_b)
    session.commit()
    session.refresh(policy_a)
    session.refresh(policy_b)

    resp_a = client.post(
        f"/api/policies/{policy_a.id}/activate",
        headers=admin_headers,
    )
    assert resp_a.status_code == 200

    resp_b = client.post(
        f"/api/policies/{policy_b.id}/activate",
        headers=admin_headers,
    )
    assert resp_b.status_code == 200

    session.expire_all()
    stmt = select(SecurityPolicy).where(SecurityPolicy.is_active == true())
    active_records = session.exec(stmt).all()

    assert len(active_records) == 1
    assert active_records[0].id == policy_b.id
