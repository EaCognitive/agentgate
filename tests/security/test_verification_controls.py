"""Security verification control tests for grant and assurance gating."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from server.models import PolicyDecisionRecord, User, VerificationGrant
from tests.router_test_support import bearer_headers, create_test_user

pytest_plugins = ("tests.router_test_support",)


@pytest.fixture(name="admin_user")
def admin_user_fixture(session: Session) -> User:
    """Create privileged user for verification endpoints."""
    return create_test_user(
        session,
        email="security-admin@test.com",
        name="Security Admin",
        password="testpass123",
        role="admin",
        is_active=True,
        tenant_id="default",
    )


def _auth_headers(user: User, assurance: str = "A1") -> dict[str, str]:
    return bearer_headers(
        user,
        assurance=assurance,
        expires_delta=timedelta(minutes=15),
    )


def test_authorize_verification_denies_low_assurance(
    client: TestClient,
    admin_user: User,
) -> None:
    """Verify that low-assurance sessions are denied verification."""
    response = client.post(
        "/api/verification/authorize",
        headers=_auth_headers(admin_user, assurance="A1"),
        json={
            "required_risk": "R2",
            "metadata": {"approval_id": "appr-123"},
        },
    )

    assert response.status_code == 403
    assert "Session assurance A1 does not satisfy required level A2" in response.json()["detail"]


def test_counterfactual_requires_grant_in_production(
    client: TestClient,
    admin_user: User,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Production mode requires a verification grant token."""
    monkeypatch.setenv("AGENTGATE_ENV", "production")
    monkeypatch.setenv("AGENTGATE_RUNTIME_PROFILE", "cloud_strict")
    monkeypatch.setenv("AGENTGATE_PROFILE", "cloud_strict")

    response = client.post(
        "/api/security/counterfactual/verify",
        headers=_auth_headers(admin_user, assurance="A3"),
        json={
            "principal": "security-admin@test.com",
            "risk_tier": "high",
            "tenant_id": "default",
            "steps": [
                {"action": "read", "resource": "tenant:default:config"},
            ],
        },
    )

    assert response.status_code == 403
    assert "verification_grant_token is required" in response.json()["detail"]


def test_counterfactual_consumes_grant_and_records_decision(
    client: TestClient,
    session: Session,
    admin_user: User,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Grant is consumed on use and the decision is recorded."""
    monkeypatch.setenv("AGENTGATE_ENV", "production")
    monkeypatch.setenv("AGENTGATE_RUNTIME_PROFILE", "cloud_strict")
    monkeypatch.setenv("AGENTGATE_PROFILE", "cloud_strict")
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    grant = VerificationGrant(
        grant_token="vgr_test_counterfactual",
        principal_id="user:security-admin",
        user_id=admin_user.id,
        tenant_id="default",
        purpose="penetration_test_counterfactual",
        risk_level="R3",
        required_assurance="A3",
        issued_at=now,
        expires_at=now + timedelta(minutes=10),
        metadata_json={"approval_id": "appr-456"},
    )
    session.add(grant)
    session.commit()
    session.refresh(grant)

    response = client.post(
        "/api/security/counterfactual/verify",
        headers=_auth_headers(admin_user, assurance="A3"),
        json={
            "principal": "security-admin@test.com",
            "risk_tier": "high",
            "tenant_id": "default",
            "verification_grant_token": grant.grant_token,
            "steps": [
                {"action": "read", "resource": "tenant:default:config"},
                {"action": "write", "resource": "tenant:default:policy"},
            ],
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    assert payload["verification_grant_consumed"] is True
    assert payload["decision_id"]

    session.refresh(grant)
    assert grant.used_at is not None

    decision = session.exec(
        select(PolicyDecisionRecord).where(
            PolicyDecisionRecord.decision_id == payload["decision_id"]
        )
    ).one_or_none()
    assert decision is not None
    assert decision.required_approval is True
