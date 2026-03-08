"""Router-focused tests for policy_governance_verification endpoints."""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import User
from server.routers import policy_governance_verification as verification_router
from tests.router_test_support import bearer_headers, create_test_user

pytest_plugins = ("tests.router_test_support",)


def _make_verification_run() -> SimpleNamespace:
    """Build a minimal verification run object used by endpoint stubs."""
    return SimpleNamespace(
        run_id="run-123",
        decision_id="decision-123",
        verification_result=True,
        details={"signature": "ok"},
        checked_at="2026-02-16T00:00:00Z",
    )


def _make_evidence_status(chain_id: str) -> SimpleNamespace:
    """Build a minimal evidence-chain verification result object."""
    return SimpleNamespace(
        chain_id=chain_id,
        valid=True,
        checked_entries=4,
        failure_reason=None,
        failed_hop_index=None,
    )


@pytest.fixture(name="admin_user")
def admin_user_fixture(session: Session) -> User:
    """Create admin user authorized for CONFIG_READ/AUDIT_READ endpoints."""
    return create_test_user(
        session,
        email="pgk-verify-admin@test.com",
        name="PGK Verify Admin",
        password="Password123!",
        role="admin",
        is_active=True,
        tenant_id="default",
    )


@pytest.fixture(name="admin_headers")
def admin_headers_fixture(admin_user: User) -> dict[str, str]:
    """Bearer token headers for admin user with high assurance."""
    return bearer_headers(
        admin_user,
        assurance="A3",
        expires_delta=timedelta(minutes=15),
    )


def test_certificate_verify_endpoint_returns_verification_payload(
    client: TestClient,
    admin_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`/certificate/verify` should return canonical verification-run structure."""

    async def _fake_verify_decision_certificate(*_args, **_kwargs):
        return _make_verification_run()

    monkeypatch.setattr(
        verification_router,
        "verify_decision_certificate",
        _fake_verify_decision_certificate,
    )

    response = client.post(
        "/api/security/certificate/verify",
        headers=admin_headers,
        json={"decision_id": "decision-123"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    assert payload["valid"] is True
    assert payload["verification_run"]["decision_id"] == "decision-123"


def test_evidence_chain_endpoint_returns_integrity_status(
    client: TestClient,
    admin_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`/evidence/chain/{chain_id}` should return integrity check metadata."""

    async def _fake_verify_evidence_chain(*_args, **_kwargs):
        return _make_evidence_status(chain_id="chain-alpha")

    monkeypatch.setattr(
        verification_router,
        "verify_evidence_chain",
        _fake_verify_evidence_chain,
    )

    response = client.get(
        "/api/security/evidence/chain/chain-alpha",
        headers=admin_headers,
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    assert payload["chain_id"] == "chain-alpha"
    assert payload["valid"] is True
    assert payload["checked_entries"] == 4


def test_counterfactual_verification_rejects_cross_tenant_step_scope(
    client: TestClient,
    admin_headers: dict[str, str],
) -> None:
    """Counterfactual verification must reject steps outside requested tenant scope."""
    response = client.post(
        "/api/security/counterfactual/verify",
        headers=admin_headers,
        json={
            "principal": "agent:verify",
            "tenant_id": "default",
            "risk_tier": "low",
            "steps": [
                {
                    "action": "read",
                    "resource": "tenant:other:config",
                    "context": {},
                }
            ],
        },
    )

    assert response.status_code == 403
    assert "outside authorized scope" in response.json()["detail"]
