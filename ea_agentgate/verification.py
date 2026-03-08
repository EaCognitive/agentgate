"""High-level formal verification API for offline proof operations.

Provides convenience functions that wrap the server-side formal security
engine so SDK users can verify certificates, check admissibility, and
validate multi-step plans without a running server.

Example::

    from ea_agentgate.verification import (
        verify_certificate,
        check_admissibility,
        verify_plan,
    )

    # Verify a previously-issued certificate offline
    ok = verify_certificate(cert_dict)

    # Quick admissibility check
    result = check_admissibility(
        principal="agent:ops",
        action="delete",
        resource="/api/users",
        policies=[{"effect": "deny", "action": "delete", "resource": "/api/*"}],
    )
    assert result.decision == "INADMISSIBLE"

    # Pre-flight plan verification
    plan_result = verify_plan(
        principal="agent:pipeline",
        steps=[
            {"action": "read", "resource": "/api/data"},
            {"action": "delete", "resource": "/api/data/old"},
        ],
        policies=my_policies,
    )
    if not plan_result.safe:
        print(f"Blocked at step {plan_result.blocked_step_index}")
"""

from __future__ import annotations

from importlib import import_module
import logging
from dataclasses import dataclass, field, fields
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from pydantic import ValidationError

from ea_agentgate.formal import (
    AlphaContext,
    DecisionCertificate,
    GammaKnowledgeBase,
    theorem_hash_for_expression,
)
from ea_agentgate.formal.helpers import extract_failed_predicates

_LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class AdmissibilityResult:
    """Result of an admissibility check.

    Attributes:
        decision: ``"ADMISSIBLE"`` or ``"INADMISSIBLE"``.
        decision_id: Unique certificate identifier.
        proof_type: ``"CONSTRUCTIVE_TRACE"`` / ``"UNSAT_CORE"`` / ``"COUNTEREXAMPLE"``.
        failed_predicates: Predicate names that caused denial.
        theorem_hash: SHA-256 of the theorem expression.
        signature: Ed25519 signature (base64-encoded).
        certificate_raw: Full certificate dict for serialization.
    """

    decision: str
    decision_id: str
    proof_type: str
    failed_predicates: list[str] = field(default_factory=list)
    theorem_hash: str = ""
    signature: str | None = None
    certificate_raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_admissible(self) -> bool:
        """Whether the request was deemed admissible."""
        return self.decision == "ADMISSIBLE"


@dataclass
class PlanVerificationResult:
    """Result of a multi-step plan verification.

    Attributes:
        safe: ``True`` if all steps are admissible.
        blocked_step_index: Index of the first blocked step (``-1`` if safe).
        blocked_reason: Reason for blocking (empty if safe).
        step_results: Per-step admissibility results.
        total_steps: Total number of steps evaluated.
    """

    safe: bool
    blocked_step_index: int = -1
    blocked_reason: str = ""
    step_results: list[AdmissibilityResult] = field(default_factory=list)
    total_steps: int = 0


@dataclass
class CertificateVerificationResult:
    """Result of offline certificate verification.

    Attributes:
        valid: ``True`` if signature and hashes are correct.
        signature_ok: Ed25519 signature verification passed.
        theorem_hash_ok: Theorem hash matches expected value.
        reason: Human-readable explanation if invalid.
    """

    valid: bool
    signature_ok: bool = False
    theorem_hash_ok: bool = False
    reason: str = ""


@dataclass
class AdmissibilityContext:
    """Policy and runtime context supplied to an admissibility check."""

    policies: list[dict[str, Any]] | None = None
    grants: list[dict[str, Any]] | None = None
    revocations: list[dict[str, Any]] | None = None
    obligations: list[dict[str, Any]] | None = None
    environment: dict[str, Any] | None = None
    tenant_id: str | None = None
    runtime_context: dict[str, Any] | None = None


_ADMISSIBILITY_CONTEXT_FIELDS = frozenset(
    field_info.name for field_info in fields(AdmissibilityContext)
)


def _build_admissibility_context(
    context: AdmissibilityContext | None,
    overrides: dict[str, Any],
) -> AdmissibilityContext:
    """Merge legacy keyword overrides into an admissibility context object."""
    resolved_context = context or AdmissibilityContext()
    if not overrides:
        return resolved_context
    unexpected = sorted(set(overrides) - _ADMISSIBILITY_CONTEXT_FIELDS)
    if unexpected:
        unknown_args = ", ".join(unexpected)
        raise TypeError(f"Unexpected admissibility arguments: {unknown_args}")
    return AdmissibilityContext(**{**resolved_context.__dict__, **overrides})


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check_admissibility(
    *,
    principal: str,
    action: str,
    resource: str,
    context: AdmissibilityContext | None = None,
    **context_overrides: Any,
) -> AdmissibilityResult:
    """Evaluate admissibility for a single action.

    Runs the 6-predicate theorem locally without needing a server.

    Args:
        principal: Agent identity (e.g. ``"agent:ops"``).
        action: The action to evaluate (e.g. ``"delete"``).
        resource: Target resource path (e.g. ``"/api/users"``).
        context: Optional grouped policy and runtime context.
        **context_overrides: Backward-compatible policy and runtime
            keyword arguments such as ``policies`` and ``tenant_id``.

    Returns:
        AdmissibilityResult with decision, proof, and certificate data.
    """
    solver_engine = import_module("server.policy_governance.kernel.solver_engine")
    evaluate = getattr(solver_engine, "evaluate_admissibility")
    admissibility_context = _build_admissibility_context(context, context_overrides)

    alpha = AlphaContext.from_runtime(
        principal=principal,
        action=action,
        resource=resource,
        runtime_context=admissibility_context.runtime_context or {},
        tenant_id=admissibility_context.tenant_id,
    )

    gamma = GammaKnowledgeBase(
        principal=principal,
        tenant_id=admissibility_context.tenant_id,
        policies=admissibility_context.policies or [],
        active_grants=admissibility_context.grants or [],
        active_revocations=admissibility_context.revocations or [],
        obligations=admissibility_context.obligations or [],
        environment=admissibility_context.environment or {},
    )

    cert = evaluate(alpha, gamma)

    failed_predicates = extract_failed_predicates(cert)

    return AdmissibilityResult(
        decision=cert.result.value,
        decision_id=str(cert.decision_id),
        proof_type=cert.proof_type.value,
        failed_predicates=failed_predicates,
        theorem_hash=cert.theorem_hash,
        signature=cert.signature,
        certificate_raw=cert.model_dump(mode="json"),
    )


def verify_certificate(
    certificate: dict[str, Any],
    *,
    public_key_pem: str | None = None,
) -> CertificateVerificationResult:
    """Verify a DecisionCertificate offline.

    Checks Ed25519 signature validity and theorem hash consistency.

    Args:
        certificate: Certificate dict (as returned by ``certificate_raw`` or
            the ``proof_certificate`` metadata entry).
        public_key_pem: Optional PEM-encoded public key. If not provided,
            derives from the default signing key.

    Returns:
        CertificateVerificationResult indicating validity.
    """
    formal_models = import_module("server.policy_governance.kernel.formal_models")
    solver_engine = import_module("server.policy_governance.kernel.solver_engine")
    load_private_key = getattr(formal_models, "load_private_key")
    theorem_expression = getattr(solver_engine, "THEOREM_EXPRESSION")

    try:
        cert = DecisionCertificate(**certificate)
    except (TypeError, ValidationError, ValueError) as exc:
        return CertificateVerificationResult(
            valid=False,
            reason=f"Invalid certificate structure: {exc}",
        )

    # Verify theorem hash
    expected_theorem_hash = theorem_hash_for_expression(theorem_expression)
    theorem_ok = cert.theorem_hash == expected_theorem_hash

    # Verify signature
    sig_ok = False
    if cert.signature:
        try:
            if public_key_pem:
                pub_key = load_pem_public_key(public_key_pem.encode("utf-8"))
            else:
                pub_key = load_private_key().public_key()
            if not isinstance(pub_key, Ed25519PublicKey):
                raise ValueError("Certificate verification requires an Ed25519 public key")
            sig_ok = cert.verify(pub_key)
        except (AttributeError, TypeError, ValueError) as exc:
            _LOG.debug("Signature verification error: %s", exc)

    valid = theorem_ok and sig_ok
    reason = ""
    if not theorem_ok:
        reason = "Theorem hash mismatch — certificate may be from a different solver version."
    elif not sig_ok:
        reason = "Signature verification failed — certificate may have been tampered with."

    return CertificateVerificationResult(
        valid=valid,
        signature_ok=sig_ok,
        theorem_hash_ok=theorem_ok,
        reason=reason,
    )


def verify_plan(
    *,
    principal: str,
    steps: list[dict[str, Any]],
    policies: list[dict[str, Any]] | None = None,
    grants: list[dict[str, Any]] | None = None,
    revocations: list[dict[str, Any]] | None = None,
    obligations: list[dict[str, Any]] | None = None,
    environment: dict[str, Any] | None = None,
    tenant_id: str | None = None,
) -> PlanVerificationResult:
    """Verify a multi-step execution plan before running it.

    Each step must contain ``action`` and ``resource`` keys. Steps are
    evaluated sequentially; verification stops at the first blocked step.

    Args:
        principal: Agent identity.
        steps: List of step dicts, each with ``action`` and ``resource``.
        policies: Policy rules applied to all steps.
        grants: Active delegation grants.
        revocations: Active revocations.
        obligations: Obligation constraints.
        environment: Environment facts.
        tenant_id: Optional tenant scope.

    Returns:
        PlanVerificationResult with per-step results and overall safety.

    Example::

        result = verify_plan(
            principal="agent:etl",
            steps=[
                {"action": "read", "resource": "/warehouse/raw"},
                {"action": "write", "resource": "/warehouse/cleaned"},
                {"action": "delete", "resource": "/warehouse/raw"},
            ],
            policies=[{"effect": "deny", "action": "delete", "resource": "/warehouse/*"}],
        )
        assert not result.safe
        assert result.blocked_step_index == 2
    """
    step_results: list[AdmissibilityResult] = []

    for idx, step in enumerate(steps):
        action = step.get("action", "")
        resource = step.get("resource", "")
        step_context = step.get("context", {})

        if not action or not resource:
            step_results.append(
                AdmissibilityResult(
                    decision="INADMISSIBLE",
                    decision_id="",
                    proof_type="COUNTEREXAMPLE",
                    failed_predicates=["missing_action_or_resource"],
                )
            )
            return PlanVerificationResult(
                safe=False,
                blocked_step_index=idx,
                blocked_reason="Step missing required 'action' or 'resource' field",
                step_results=step_results,
                total_steps=len(steps),
            )

        result = check_admissibility(
            principal=principal,
            action=action,
            resource=resource,
            policies=policies,
            grants=grants,
            revocations=revocations,
            obligations=obligations,
            environment=environment,
            tenant_id=tenant_id,
            runtime_context=step_context,
        )
        step_results.append(result)

        if not result.is_admissible:
            reason = (
                ", ".join(result.failed_predicates) if result.failed_predicates else "INADMISSIBLE"
            )
            return PlanVerificationResult(
                safe=False,
                blocked_step_index=idx,
                blocked_reason=reason,
                step_results=step_results,
                total_steps=len(steps),
            )

    return PlanVerificationResult(
        safe=True,
        blocked_step_index=-1,
        step_results=step_results,
        total_steps=len(steps),
    )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------
__all__ = [
    "AdmissibilityResult",
    "CertificateVerificationResult",
    "PlanVerificationResult",
    "check_admissibility",
    "verify_certificate",
    "verify_plan",
]
