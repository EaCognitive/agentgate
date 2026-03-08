"""Contract tests for canonical formal API paths and compatibility aliases."""

from __future__ import annotations

import urllib.parse
from argparse import Namespace

import pytest
from fastapi import HTTPException, Response

from ea_agentgate.cli import cmd_formal
from server.routers import policy_governance, policy_governance_verification
from server.routers.policy_governance_verification import CertificateVerifyRequest


class _FakeCliClient:
    """Minimal client stub for formal CLI endpoint contract tests."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict | None]] = []

    def post(self, path: str, body: dict | None = None):
        """Record POST calls and return canned formal API responses."""
        self.calls.append(("post", path, body))
        if path == "/api/security/admissibility/evaluate":
            return {
                "success": True,
                "certificate": {
                    "decision_id": "dec-remote",
                    "result": "ADMISSIBLE",
                    "proof_type": "CONSTRUCTIVE_TRACE",
                    "theorem_hash": "abc",
                },
                "runtime_solver": {"solver_mode": "enforce", "solver_backend": "z3"},
            }
        return {"valid": True}

    def get(self, path: str, params: dict | None = None):
        """Record GET calls and return canned evidence responses."""
        _ = params
        self.calls.append(("get", path, None))
        return {"valid": True, "entries_verified": 2}

    def formal_evaluate_admissibility(
        self,
        *,
        principal: str,
        action: str,
        resource: str,
        runtime_context: dict | None = None,
        delegation_ref: str | None = None,
        tenant_id: str | None = None,
        chain_id: str = "sdk-formal-evaluation",
    ):
        """Mirror the SDK formal evaluation method against the stubbed client."""
        return self.post(
            "/api/security/admissibility/evaluate",
            body={
                "principal": principal,
                "action": action,
                "resource": resource,
                "runtime_context": runtime_context or {},
                "delegation_ref": delegation_ref,
                "tenant_id": tenant_id,
                "chain_id": chain_id,
            },
        )

    def formal_verify_certificate(self, decision_id: str):
        """Mirror the SDK certificate verification method."""
        return self.post(
            "/api/security/certificate/verify",
            body={"decision_id": decision_id},
        )

    def formal_verify_evidence_chain(self, chain_id: str = "global"):
        """Mirror the SDK evidence verification method with URL quoting."""
        quoted = urllib.parse.quote(chain_id, safe="")
        return self.get(f"/api/security/evidence/chain/{quoted}")


def test_cmd_verify_uses_canonical_endpoint() -> None:
    """CLI formal verify must call canonical certificate endpoint."""
    client = _FakeCliClient()
    args = Namespace(decision_id="dec-1", json=True)

    cmd_formal.cmd_verify(args, client)  # type: ignore[arg-type]

    assert client.calls == [
        ("post", "/api/security/certificate/verify", {"decision_id": "dec-1"}),
    ]


def test_cmd_evidence_uses_canonical_endpoint() -> None:
    """CLI formal evidence must call canonical evidence endpoint with quoted chain_id."""
    client = _FakeCliClient()
    args = Namespace(chain_id="tenant/a b", json=True)

    cmd_formal.cmd_evidence(args, client)  # type: ignore[arg-type]

    assert client.calls == [
        ("get", "/api/security/evidence/chain/tenant%2Fa%20b", None),
    ]


def test_cmd_check_remote_uses_canonical_endpoint() -> None:
    """CLI formal check uses remote canonical endpoint by default."""
    client = _FakeCliClient()
    args = Namespace(
        principal="agent:test",
        action="config:read",
        resource="tenant/default/config",
        policies=None,
        tenant_id="default",
        provider="remote",
        json=True,
    )

    cmd_formal.cmd_check(args, client)  # type: ignore[arg-type]

    assert client.calls == [
        (
            "post",
            "/api/security/admissibility/evaluate",
            {
                "principal": "agent:test",
                "action": "config:read",
                "resource": "tenant/default/config",
                "runtime_context": {},
                "delegation_ref": None,
                "tenant_id": "default",
                "chain_id": "sdk-formal-evaluation",
            },
        ),
    ]


@pytest.mark.asyncio
async def test_verify_legacy_alias_wraps_canonical_response(monkeypatch) -> None:
    """Legacy verify alias should map canonical response shape to legacy fields."""

    async def _fake_verify(_payload, _current_user, _session):
        return {
            "success": True,
            "verification_run": {
                "decision_id": "dec-legacy",
                "verification_result": True,
            },
        }

    monkeypatch.setattr(policy_governance_verification, "verify_certificate", _fake_verify)

    payload = CertificateVerifyRequest(decision_id="dec-legacy")
    result = await policy_governance_verification.verify_certificate_legacy(
        payload,
        response=Response(),
        current_user=object(),  # type: ignore[arg-type]
        session=object(),  # type: ignore[arg-type]
    )

    assert result["valid"] is True
    assert result["decision_id"] == "dec-legacy"
    assert result["verification_run"]["verification_result"] is True


@pytest.mark.asyncio
async def test_evidence_legacy_alias_wraps_canonical_response(monkeypatch) -> None:
    """Legacy evidence alias should map canonical response shape to legacy fields."""

    async def _fake_status(_chain_id, _current_user, _session):
        return {
            "chain_id": "global",
            "valid": True,
            "checked_entries": 5,
            "failure_reason": None,
            "failed_hop_index": None,
        }

    monkeypatch.setattr(policy_governance_verification, "get_evidence_chain_status", _fake_status)

    result = await policy_governance_verification.get_evidence_chain_status_legacy(
        response=Response(),
        chain_id="global",
        current_user=object(),
        session=object(),
    )

    assert result["valid"] is True
    assert result["integrity_verified"] is True
    assert result["entries_verified"] == 5
    assert result["total_entries"] == 5


@pytest.mark.asyncio
async def test_runtime_status_endpoint_uses_solver_validation(monkeypatch) -> None:
    """Runtime status endpoint returns validated runtime Z3 diagnostics."""

    monkeypatch.setattr(
        policy_governance,
        "validate_runtime_z3_configuration",
        lambda require_solver_health: {
            "configured_mode": "enforce",
            "environment": "production",
            "off_mode_allowed": False,
            "z3_available": True,
            "z3_healthy": True,
            "z3_check_result": "sat",
            "z3_error": None,
        },
    )

    result = await policy_governance.admissibility_runtime_status(current_user=object())
    assert result.configured_mode == "enforce"
    assert result.environment == "production"
    assert result.z3_available is True


@pytest.mark.asyncio
async def test_runtime_status_endpoint_reports_misconfiguration(monkeypatch) -> None:
    """Runtime status endpoint must return explicit misconfiguration errors."""

    def _raise_runtime_error(*, require_solver_health: bool):
        _ = require_solver_health
        raise RuntimeError("AGENTGATE_Z3_MODE=off is restricted to local/dev/test runtimes.")

    monkeypatch.setattr(
        policy_governance,
        "validate_runtime_z3_configuration",
        _raise_runtime_error,
    )

    with pytest.raises(HTTPException) as exc_info:
        await policy_governance.admissibility_runtime_status(current_user=object())

    assert exc_info.value.status_code == 500
    detail = exc_info.value.detail
    assert detail["error"] == "runtime_solver_misconfigured"
    assert "restricted to local/dev/test" in detail["message"]
