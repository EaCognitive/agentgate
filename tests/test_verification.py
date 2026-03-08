"""Tests for the formal verification SDK integration.

Covers:
- ea_agentgate.verification module (check_admissibility, verify_certificate, verify_plan)
- Agent with formal_verification=True (auto-injection, last_certificate, callback)
"""

from __future__ import annotations

import copy
from unittest.mock import MagicMock

import pytest

from ea_agentgate.agent import Agent
from ea_agentgate.middleware.proof_middleware import (
    AdmissibilityDeniedError,
    ProofCarryingMiddleware,
)
from ea_agentgate.verification import (
    AdmissibilityResult,
    CertificateVerificationResult,
    PlanVerificationResult,
    check_admissibility,
    verify_certificate,
    verify_plan,
)

# ---------------------------------------------------------------------------
# Fixtures: build solver-compatible domain objects
# ---------------------------------------------------------------------------


def _permit_policy(action: str = "*", resource: str = "*") -> dict:
    """A simple permit policy rule in solver-compatible format."""
    return {
        "policy_json": {"pre_rules": [{"type": "permit", "action": action, "resource": resource}]}
    }


def _deny_policy(action: str = "delete", resource: str = "/prod/*") -> dict:
    """A simple deny policy rule in solver-compatible format."""
    return {
        "policy_json": {"pre_rules": [{"type": "deny", "action": action, "resource": resource}]}
    }


# =========================================================================
# Module: ea_agentgate.verification
# =========================================================================


class TestCheckAdmissibility:
    """Tests for check_admissibility()."""

    def test_admissible_with_permit(self):
        """Permit policy yields ADMISSIBLE with a signed certificate."""
        result = check_admissibility(
            principal="agent:test",
            action="read",
            resource="/api/data",
            policies=[_permit_policy()],
        )
        assert isinstance(result, AdmissibilityResult)
        assert result.is_admissible
        assert result.decision == "ADMISSIBLE"
        assert result.decision_id  # non-empty
        assert result.proof_type == "CONSTRUCTIVE_TRACE"
        assert result.theorem_hash
        assert result.signature  # Ed25519 signed
        assert result.certificate_raw  # full dict present

    def test_inadmissible_with_deny(self):
        """Deny policy causes INADMISSIBLE with failed predicates."""
        result = check_admissibility(
            principal="agent:test",
            action="delete",
            resource="/prod/db",
            policies=[_permit_policy(), _deny_policy()],
        )
        assert not result.is_admissible
        assert result.decision == "INADMISSIBLE"
        assert result.proof_type in ("COUNTEREXAMPLE", "UNSAT_CORE")
        assert len(result.failed_predicates) > 0

    def test_inadmissible_no_policies(self):
        """No policies uses unconfigured fallback and remains admissible."""
        result = check_admissibility(
            principal="agent:test",
            action="read",
            resource="/api/data",
            policies=[],
        )
        assert result.is_admissible

    def test_with_tenant_id(self):
        """Tenant-scoped check still resolves admissibility."""
        result = check_admissibility(
            principal="agent:test",
            action="read",
            resource="/api/data",
            policies=[_permit_policy()],
            tenant_id="acme-corp",
        )
        assert result.is_admissible

    def test_with_runtime_context(self):
        """Runtime context is accepted without affecting admissibility."""
        result = check_admissibility(
            principal="agent:test",
            action="read",
            resource="/api/data",
            policies=[_permit_policy()],
            runtime_context={"ip": "10.0.0.1", "region": "us-east"},
        )
        assert result.is_admissible


class TestVerifyCertificate:
    """Tests for verify_certificate()."""

    def test_valid_certificate(self):
        """Certificate from check_admissibility should verify cleanly."""
        adm = check_admissibility(
            principal="agent:test",
            action="read",
            resource="/api/data",
            policies=[_permit_policy()],
        )
        result = verify_certificate(adm.certificate_raw)
        assert isinstance(result, CertificateVerificationResult)
        assert result.valid
        assert result.signature_ok
        assert result.theorem_hash_ok
        assert result.reason == ""

    def test_tampered_signature(self):
        """Tampering with signature should fail verification."""
        adm = check_admissibility(
            principal="agent:test",
            action="read",
            resource="/api/data",
            policies=[_permit_policy()],
        )
        cert = copy.deepcopy(adm.certificate_raw)
        cert["signature"] = "AAAA" + cert["signature"][4:]  # tamper
        result = verify_certificate(cert)
        assert not result.valid
        assert not result.signature_ok

    def test_tampered_theorem_hash(self):
        """Wrong theorem hash should be detected."""
        adm = check_admissibility(
            principal="agent:test",
            action="read",
            resource="/api/data",
            policies=[_permit_policy()],
        )
        cert = copy.deepcopy(adm.certificate_raw)
        cert["theorem_hash"] = "a" * 64  # wrong hash
        result = verify_certificate(cert)
        assert not result.valid
        assert not result.theorem_hash_ok
        assert "theorem hash" in result.reason.lower()

    def test_invalid_structure(self):
        """Garbage input should fail gracefully."""
        result = verify_certificate({"foo": "bar"})
        assert not result.valid
        assert "invalid certificate" in result.reason.lower()

    def test_missing_signature(self):
        """Certificate without signature should fail."""
        adm = check_admissibility(
            principal="agent:test",
            action="read",
            resource="/api/data",
            policies=[_permit_policy()],
        )
        cert = copy.deepcopy(adm.certificate_raw)
        cert["signature"] = None
        result = verify_certificate(cert)
        assert not result.valid
        assert not result.signature_ok


class TestVerifyPlan:
    """Tests for verify_plan()."""

    def test_all_steps_admissible(self):
        """Plan with all permitted steps is marked safe."""
        result = verify_plan(
            principal="agent:test",
            steps=[
                {"action": "read", "resource": "/api/data"},
                {"action": "write", "resource": "/api/data"},
            ],
            policies=[_permit_policy()],
        )
        assert isinstance(result, PlanVerificationResult)
        assert result.safe
        assert result.blocked_step_index == -1
        assert result.total_steps == 2
        assert len(result.step_results) == 2
        assert all(r.is_admissible for r in result.step_results)

    def test_blocked_at_second_step(self):
        """First step allowed, second denied."""
        result = verify_plan(
            principal="agent:test",
            steps=[
                {"action": "read", "resource": "/api/data"},
                {"action": "delete", "resource": "/prod/db"},
            ],
            policies=[_permit_policy(), _deny_policy()],
        )
        assert not result.safe
        assert result.blocked_step_index == 1
        assert result.total_steps == 2
        assert len(result.step_results) == 2
        assert result.step_results[0].is_admissible
        assert not result.step_results[1].is_admissible

    def test_blocked_at_first_step(self):
        """Deny at first step → stops immediately."""
        result = verify_plan(
            principal="agent:test",
            steps=[
                {"action": "delete", "resource": "/prod/db"},
                {"action": "read", "resource": "/api/data"},
            ],
            policies=[_permit_policy(), _deny_policy()],
        )
        assert not result.safe
        assert result.blocked_step_index == 0
        assert len(result.step_results) == 1  # didn't evaluate second step

    def test_empty_plan(self):
        """Empty plan is trivially safe."""
        result = verify_plan(
            principal="agent:test",
            steps=[],
            policies=[_permit_policy()],
        )
        assert result.safe
        assert result.total_steps == 0

    def test_missing_action_in_step(self):
        """Step without action key → treated as inadmissible."""
        result = verify_plan(
            principal="agent:test",
            steps=[{"resource": "/api/data"}],
            policies=[_permit_policy()],
        )
        assert not result.safe
        assert result.blocked_step_index == 0

    def test_three_step_plan_blocked_at_third(self):
        """Multi-step plan with denial at the end."""
        result = verify_plan(
            principal="agent:test",
            steps=[
                {"action": "read", "resource": "/api/users"},
                {"action": "write", "resource": "/api/users"},
                {"action": "delete", "resource": "/prod/users"},
            ],
            policies=[_permit_policy(), _deny_policy()],
        )
        assert not result.safe
        assert result.blocked_step_index == 2
        assert len(result.step_results) == 3


# =========================================================================
# Agent: formal_verification integration
# =========================================================================


class TestAgentFormalVerification:
    """Tests for Agent with formal_verification=True."""

    def test_requires_principal(self):
        """formal_verification=True without principal should raise."""
        with pytest.raises(ValueError, match="principal"):
            Agent(formal_verification=True)

    def test_auto_injects_proof_middleware(self):
        """ProofCarryingMiddleware should be auto-injected as first middleware."""
        agent = Agent(
            formal_verification=True,
            principal="agent:test",
            policies=[_permit_policy()],
        )
        assert agent.formal_verification is True
        assert len(agent.middleware) >= 1
        assert isinstance(agent.middleware[0], ProofCarryingMiddleware)

    def test_proof_middleware_prepended(self):
        """ProofCarryingMiddleware should come before user middleware."""
        dummy_mw = MagicMock()
        dummy_mw.before = MagicMock(return_value=None)
        dummy_mw.after = MagicMock(return_value=None)
        dummy_mw.failure_mode = None

        agent = Agent(
            middleware=[dummy_mw],
            formal_verification=True,
            principal="agent:test",
            policies=[_permit_policy()],
        )
        assert isinstance(agent.middleware[0], ProofCarryingMiddleware)
        assert agent.middleware[1] is dummy_mw

    def test_last_certificate_initially_none(self):
        """Agent starts with no certificate before any calls."""
        agent = Agent(
            formal_verification=True,
            principal="agent:test",
            policies=[_permit_policy()],
        )
        assert agent.last_certificate is None

    def test_admissible_call_sets_certificate(self):
        """Successful call should populate last_certificate."""
        agent = Agent(
            formal_verification=True,
            principal="agent:test",
            policies=[_permit_policy()],
        )

        @agent.tool
        def greet(name: str) -> str:
            return f"Hello {name}"

        result = agent.call("greet", name="world")
        assert result == "Hello world"

        cert = agent.last_certificate
        assert cert is not None
        assert cert["result"] == "ADMISSIBLE"
        assert cert["proof_type"] == "CONSTRUCTIVE_TRACE"
        assert cert["decision_id"]
        assert cert["signature"]

    def test_inadmissible_call_raises_and_sets_certificate(self):
        """INADMISSIBLE call should raise and still capture certificate."""
        agent = Agent(
            formal_verification=True,
            principal="agent:test",
            policies=[_permit_policy(), _deny_policy()],
        )

        @agent.tool(name="delete")
        def delete_item(resource: str) -> str:
            return f"Deleted {resource}"

        with pytest.raises(AdmissibilityDeniedError) as exc_info:
            agent.call("delete", resource="/prod/important")

        assert exc_info.value.result == "INADMISSIBLE"
        # Certificate should be captured even on denial
        cert = agent.last_certificate
        assert cert is not None
        assert cert["result"] == "INADMISSIBLE"

    def test_certificate_callback_invoked(self):
        """certificate_callback should be called with each new certificate."""
        captured = []

        def on_cert(cert_dict):
            captured.append(cert_dict)

        agent = Agent(
            formal_verification=True,
            principal="agent:test",
            policies=[_permit_policy()],
            certificate_callback=on_cert,
        )

        @agent.tool
        def noop() -> str:
            return "ok"

        agent.call("noop")
        assert len(captured) == 1
        assert captured[0]["result"] == "ADMISSIBLE"

        agent.call("noop")
        assert len(captured) == 2

    def test_verify_last_certificate(self):
        """verify_last_certificate should return True for valid certs."""
        agent = Agent(
            formal_verification=True,
            principal="agent:test",
            policies=[_permit_policy()],
        )

        @agent.tool
        def noop() -> str:
            return "ok"

        agent.call("noop")
        assert agent.verify_last_certificate() is True

    def test_verify_last_certificate_none(self):
        """verify_last_certificate should return False when no cert."""
        agent = Agent(
            formal_verification=True,
            principal="agent:test",
            policies=[_permit_policy()],
        )
        assert agent.verify_last_certificate() is False

    def test_shadow_mode(self):
        """Shadow mode should not block INADMISSIBLE calls."""
        agent = Agent(
            formal_verification=True,
            principal="agent:test",
            policies=[_permit_policy(), _deny_policy()],
            verification_mode="shadow",
        )

        @agent.tool(name="delete")
        def delete_item(resource: str) -> str:
            return f"Deleted {resource}"

        # Should not raise in shadow mode
        result = agent.call("delete", resource="/prod/important")
        assert result == "Deleted /prod/important"

        cert = agent.last_certificate
        assert cert is not None
        assert cert["result"] == "INADMISSIBLE"  # still records

    def test_formal_verification_disabled_by_default(self):
        """Default Agent should not have formal verification."""
        agent = Agent()
        assert agent.formal_verification is False
        assert agent.last_certificate is None

    @pytest.mark.asyncio
    async def test_async_admissible_call(self):
        """Async call should also capture certificates."""
        agent = Agent(
            formal_verification=True,
            principal="agent:test",
            policies=[_permit_policy()],
        )

        @agent.tool
        async def async_greet(name: str) -> str:
            return f"Hello {name}"

        result = await agent.acall("async_greet", name="async-world")
        assert result == "Hello async-world"

        cert = agent.last_certificate
        assert cert is not None
        assert cert["result"] == "ADMISSIBLE"

    @pytest.mark.asyncio
    async def test_async_inadmissible_call(self):
        """Async INADMISSIBLE call should raise and capture cert."""
        agent = Agent(
            formal_verification=True,
            principal="agent:test",
            policies=[_permit_policy(), _deny_policy()],
        )

        @agent.tool(name="delete")
        async def delete_item(resource: str) -> str:
            return f"Deleted {resource}"

        with pytest.raises(AdmissibilityDeniedError):
            await agent.acall("delete", resource="/prod/db")

        cert = agent.last_certificate
        assert cert is not None
        assert cert["result"] == "INADMISSIBLE"


# =========================================================================
# Edge cases
# =========================================================================


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_callback_error_does_not_break_call(self):
        """If callback raises, tool call should still succeed."""

        def bad_callback(cert):
            raise RuntimeError("callback boom")

        agent = Agent(
            formal_verification=True,
            principal="agent:test",
            policies=[_permit_policy()],
            certificate_callback=bad_callback,
        )

        @agent.tool
        def noop() -> str:
            return "ok"

        # Should not raise despite callback error
        result = agent.call("noop")
        assert result == "ok"

    def test_multiple_calls_update_certificate(self):
        """Each call should update last_certificate."""
        agent = Agent(
            formal_verification=True,
            principal="agent:test",
            policies=[_permit_policy()],
        )

        @agent.tool
        def tool_a() -> str:
            return "a"

        @agent.tool
        def tool_b() -> str:
            return "b"

        agent.call("tool_a")
        cert_a = agent.last_certificate
        assert cert_a is not None

        agent.call("tool_b")
        cert_b = agent.last_certificate
        assert cert_b is not None

        # Different calls should produce different decision IDs
        assert cert_a["decision_id"] != cert_b["decision_id"]

    def test_deny_wins_over_permit(self):
        """Deny policy should override matching permit (deny-wins semantics)."""
        result = check_admissibility(
            principal="agent:test",
            action="delete",
            resource="/prod/db",
            policies=[
                _permit_policy("delete", "/prod/*"),
                _deny_policy("delete", "/prod/*"),
            ],
        )
        assert not result.is_admissible

    def test_scoped_deny_no_overblock(self):
        """Deny on /prod/* should not block /staging/*."""
        result = check_admissibility(
            principal="agent:test",
            action="delete",
            resource="/staging/cache",
            policies=[
                _permit_policy(),
                _deny_policy("delete", "/prod/*"),
            ],
        )
        assert result.is_admissible
