"""Tests for certificate lookup and stats endpoints."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

from server.main import app
from server.models import (
    DecisionCertificateRecord,
    User,
    get_session,
)
from server.routers.auth import create_access_token
from server.routers.auth_utils import (
    _get_password_hash_sync as get_password_hash,
)


@pytest.fixture(name="session")
def session_fixture() -> Session:
    """Create isolated in-memory SQLModel session."""
    eng = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(eng)
    sess = Session(eng)
    try:
        yield sess
    finally:
        sess.close()
        eng.dispose()


@pytest.fixture(name="client")
def client_fixture(session: Session) -> TestClient:
    """Create TestClient with DB dependency override."""

    def get_session_override():
        return session

    app.dependency_overrides[get_session] = get_session_override
    cli = TestClient(app)
    try:
        yield cli
    finally:
        app.dependency_overrides.clear()


@pytest.fixture(name="admin_user")
def admin_user_fixture(session: Session) -> User:
    """Create admin user authorized for CONFIG_READ."""
    user = User(
        email="cert-lookup-admin@test.com",
        name="Cert Lookup Admin",
        hashed_password=get_password_hash("Password123!"),
        role="admin",
        is_active=True,
        tenant_id="default",
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@pytest.fixture(name="admin_headers")
def admin_headers_fixture(admin_user: User) -> dict[str, str]:
    """Bearer token headers with high assurance."""
    token = create_access_token(
        data={
            "sub": admin_user.email,
            "role": admin_user.role,
            "session_assurance": "A3",
        },
        expires_delta=timedelta(minutes=15),
    )
    return {"Authorization": f"Bearer {token}"}


_DEFAULT_CERTIFICATE_FIELDS: dict[str, object] = {
    "result": "admissible",
    "proof_type": "smt_proof",
    "alpha_hash": "alpha000",
    "gamma_hash": "gamma000",
    "theorem_hash": "thm000",
    "principal": "agent:test",
    "action": "read",
    "resource": "data:test",
    "tenant_id": "default",
    "solver_version": "v1.0",
    "signature": "sig-placeholder",
    "proof_payload": {},
    "certificate_json": {},
}


def _build_certificate_fields(**overrides: object) -> dict[str, object]:
    """Return certificate fields merged over the module defaults."""
    certificate_fields = deepcopy(_DEFAULT_CERTIFICATE_FIELDS)
    certificate_fields.update(overrides)
    return certificate_fields


def _make_certificate(
    session: Session,
    *,
    decision_id: str,
    created_at: datetime | None = None,
    **overrides: object,
) -> DecisionCertificateRecord:
    """Insert a DecisionCertificateRecord and return it."""
    cert = DecisionCertificateRecord(
        decision_id=decision_id,
        **_build_certificate_fields(**overrides),
    )
    if created_at is not None:
        cert.created_at = created_at
    session.add(cert)
    session.commit()
    session.refresh(cert)
    return cert


# ------------------------------------------------------------------
# GET /certificates/{decision_id}
# ------------------------------------------------------------------


def test_get_certificate_by_id_200(
    client: TestClient,
    admin_headers: dict[str, str],
    session: Session,
) -> None:
    """Retrieve a certificate by decision_id returns all fields."""
    cert = _make_certificate(
        session,
        decision_id="dec-001",
        result="admissible",
        proof_type="smt_proof",
        alpha_hash="alpha-a",
        gamma_hash="gamma-a",
        theorem_hash="thm-a",
        principal="agent:alpha",
        action="read",
        resource="data:secrets",
        tenant_id="tenant-x",
        solver_version="v2.0",
        signature="sig-dec-001",
    )
    resp = client.get(
        f"/api/security/certificates/{cert.decision_id}",
        headers=admin_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    c = body["certificate"]
    assert c["decision_id"] == "dec-001"
    assert c["result"] == "admissible"
    assert c["proof_type"] == "smt_proof"
    assert c["alpha_hash"] == "alpha-a"
    assert c["gamma_hash"] == "gamma-a"
    assert c["theorem_hash"] == "thm-a"
    assert c["principal"] == "agent:alpha"
    assert c["action"] == "read"
    assert c["resource"] == "data:secrets"
    assert c["tenant_id"] == "tenant-x"
    assert c["solver_version"] == "v2.0"
    assert c["signature"] == "sig-dec-001"
    assert "created_at" in c


def test_get_certificate_404(
    client: TestClient,
    admin_headers: dict[str, str],
) -> None:
    """GET nonexistent certificate returns 404."""
    resp = client.get(
        "/api/security/certificates/nonexistent-id",
        headers=admin_headers,
    )
    assert resp.status_code == 404


def test_get_certificate_401(
    client: TestClient,
) -> None:
    """GET certificate without auth returns 401."""
    resp = client.get(
        "/api/security/certificates/any-id",
    )
    assert resp.status_code == 401


# ------------------------------------------------------------------
# GET /certificates/lookup
# ------------------------------------------------------------------


def test_lookup_by_alpha_hash(
    client: TestClient,
    admin_headers: dict[str, str],
    session: Session,
) -> None:
    """Lookup by alpha_hash returns only matching certs."""
    _make_certificate(
        session,
        decision_id="dec-a1",
        alpha_hash="alpha-match",
    )
    _make_certificate(
        session,
        decision_id="dec-a2",
        alpha_hash="alpha-other",
    )
    resp = client.get(
        "/api/security/certificates/lookup",
        headers=admin_headers,
        params={"alpha_hash": "alpha-match"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    assert body["certificates"][0]["decision_id"] == "dec-a1"


def test_lookup_by_gamma_hash(
    client: TestClient,
    admin_headers: dict[str, str],
    session: Session,
) -> None:
    """Lookup by gamma_hash returns only matching certs."""
    _make_certificate(
        session,
        decision_id="dec-g1",
        gamma_hash="gamma-match",
    )
    _make_certificate(
        session,
        decision_id="dec-g2",
        gamma_hash="gamma-other",
    )
    resp = client.get(
        "/api/security/certificates/lookup",
        headers=admin_headers,
        params={"gamma_hash": "gamma-match"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    assert body["certificates"][0]["decision_id"] == "dec-g1"


def test_lookup_by_theorem_hash(
    client: TestClient,
    admin_headers: dict[str, str],
    session: Session,
) -> None:
    """Lookup by theorem_hash returns only matching certs."""
    _make_certificate(
        session,
        decision_id="dec-t1",
        theorem_hash="thm-match",
    )
    _make_certificate(
        session,
        decision_id="dec-t2",
        theorem_hash="thm-other",
    )
    resp = client.get(
        "/api/security/certificates/lookup",
        headers=admin_headers,
        params={"theorem_hash": "thm-match"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    assert body["certificates"][0]["decision_id"] == "dec-t1"


def test_lookup_combined_hashes(
    client: TestClient,
    admin_headers: dict[str, str],
    session: Session,
) -> None:
    """Lookup with multiple hash params uses AND logic."""
    _make_certificate(
        session,
        decision_id="dec-c1",
        alpha_hash="alpha-x",
        gamma_hash="gamma-x",
    )
    _make_certificate(
        session,
        decision_id="dec-c2",
        alpha_hash="alpha-x",
        gamma_hash="gamma-y",
    )
    resp = client.get(
        "/api/security/certificates/lookup",
        headers=admin_headers,
        params={
            "alpha_hash": "alpha-x",
            "gamma_hash": "gamma-x",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    assert body["certificates"][0]["decision_id"] == "dec-c1"


def test_lookup_no_params_422(
    client: TestClient,
    admin_headers: dict[str, str],
) -> None:
    """Lookup with no hash params returns 422."""
    resp = client.get(
        "/api/security/certificates/lookup",
        headers=admin_headers,
    )
    assert resp.status_code == 422


def test_lookup_empty_result(
    client: TestClient,
    admin_headers: dict[str, str],
) -> None:
    """Lookup with non-matching hash returns empty array."""
    resp = client.get(
        "/api/security/certificates/lookup",
        headers=admin_headers,
        params={"alpha_hash": "no-such-hash"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 0
    assert body["certificates"] == []


def test_lookup_respects_limit(
    client: TestClient,
    admin_headers: dict[str, str],
    session: Session,
) -> None:
    """Lookup with limit=2 returns at most 2 certificates."""
    for i in range(5):
        _make_certificate(
            session,
            decision_id=f"dec-lim-{i}",
            alpha_hash="alpha-shared",
        )
    resp = client.get(
        "/api/security/certificates/lookup",
        headers=admin_headers,
        params={"alpha_hash": "alpha-shared", "limit": 2},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 2


def test_lookup_401(
    client: TestClient,
) -> None:
    """Lookup without auth returns 401."""
    resp = client.get(
        "/api/security/certificates/lookup",
        params={"alpha_hash": "any"},
    )
    assert resp.status_code == 401


# ------------------------------------------------------------------
# GET /certificates/stats
# ------------------------------------------------------------------


def test_stats_aggregate_counts(
    client: TestClient,
    admin_headers: dict[str, str],
    session: Session,
) -> None:
    """Stats returns correct aggregate counts."""
    _make_certificate(
        session,
        decision_id="dec-s1",
        result="admissible",
    )
    _make_certificate(
        session,
        decision_id="dec-s2",
        result="admissible",
    )
    _make_certificate(
        session,
        decision_id="dec-s3",
        result="inadmissible",
    )
    resp = client.get(
        "/api/security/certificates/stats",
        headers=admin_headers,
        params={"hours": 720},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    assert body["total_decisions"] == 3
    assert body["admissible"] == 2
    assert body["inadmissible"] == 1
    assert body["by_result"]["admissible"] == 2
    assert body["by_result"]["inadmissible"] == 1


def test_stats_by_proof_type(
    client: TestClient,
    admin_headers: dict[str, str],
    session: Session,
) -> None:
    """Stats returns correct breakdown by proof_type."""
    _make_certificate(
        session,
        decision_id="dec-p1",
        proof_type="smt_proof",
    )
    _make_certificate(
        session,
        decision_id="dec-p2",
        proof_type="smt_proof",
    )
    _make_certificate(
        session,
        decision_id="dec-p3",
        proof_type="model_check",
    )
    resp = client.get(
        "/api/security/certificates/stats",
        headers=admin_headers,
        params={"hours": 720},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["by_proof_type"]["smt_proof"] == 2
    assert body["by_proof_type"]["model_check"] == 1


def test_stats_empty_zero_counts(
    client: TestClient,
    admin_headers: dict[str, str],
) -> None:
    """Stats with no certificates returns all zeros."""
    resp = client.get(
        "/api/security/certificates/stats",
        headers=admin_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_decisions"] == 0
    assert body["admissible"] == 0
    assert body["inadmissible"] == 0
    assert body["by_result"] == {}
    assert body["by_proof_type"] == {}


def test_stats_401(
    client: TestClient,
) -> None:
    """Stats without auth returns 401."""
    resp = client.get(
        "/api/security/certificates/stats",
    )
    assert resp.status_code == 401
