"""Unified proof-carrying enforcement entrypoints.

All side-effecting action paths should invoke this module to ensure decisions
are evaluated against formal admissibility and persisted with signed evidence.
Includes honey-token deception detection and optional consensus verification.
"""

from __future__ import annotations

import asyncio
from importlib import import_module
import logging
from dataclasses import dataclass
from typing import Any

from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import AsyncSession

from server.audit import emit_audit_event
from server.models.database import get_session_context
from server.models.formal_security_schemas import (
    CoSignatureRecord,
    CounterexampleTrace,
    DecisionCertificateRecord,
    DeceptionTriggerRecord,
    DelegationGrant,
    DelegationRevocation,
    ExecutionEvidenceChain,
    GlobalRevocationRecord,
    HoneyTokenRecord,
    ProofVerificationRun,
    SafetyNodeRecord,
    SynthesizedInvariantRecord,
    TransparencyLogRecord,
)
from .deception_injector import (
    TrustDegradation,
    apply_trust_degradation,
    check_action_against_tokens,
    determine_severity,
    load_honey_tokens,
    record_deception_trigger,
)
from .evidence_log import append_decision_evidence
from .formal_models import (
    AlphaContext,
    DecisionCertificate,
    DecisionResult,
    ProofType,
    canonical_json,
    load_private_key,
    sha256_hex,
    theorem_hash_for_expression,
)
from .gamma_builder import GammaBuildResult, GammaBuilder
from .solver_engine import THEOREM_EXPRESSION, evaluate_admissibility

logger = logging.getLogger(__name__)

_FORMAL_SCHEMA_LOCK = asyncio.Lock()
_FORMAL_SCHEMA_READY: set[int] = set()
_FORMAL_SECURITY_MODELS = [
    DelegationGrant,
    DelegationRevocation,
    DecisionCertificateRecord,
    ExecutionEvidenceChain,
    CounterexampleTrace,
    ProofVerificationRun,
    SynthesizedInvariantRecord,
    HoneyTokenRecord,
    DeceptionTriggerRecord,
    SafetyNodeRecord,
    TransparencyLogRecord,
    CoSignatureRecord,
    GlobalRevocationRecord,
]
_FORMAL_SECURITY_TABLES = [getattr(model, "__table__") for model in _FORMAL_SECURITY_MODELS]
_FORMAL_SECURITY_TABLE_NAMES = {table.name for table in _FORMAL_SECURITY_TABLES}


class SecurityEnforcementError(RuntimeError):
    """Raised when a decision is inadmissible during enforcement."""

    def __init__(self, message: str, certificate: DecisionCertificate):
        super().__init__(message)
        self.certificate = certificate


@dataclass(slots=True)
class EnforcementResult:
    """Proof enforcement output for successful evaluations."""

    alpha: AlphaContext
    gamma: GammaBuildResult
    certificate: DecisionCertificate


def _normalize_runtime_context(runtime_context: dict[str, Any] | None) -> dict[str, Any]:
    """Normalize runtime context with deterministic enforcement defaults."""
    context = dict(runtime_context or {})
    context.setdefault("authenticated", True)
    context.setdefault("direct_access", True)
    context.setdefault("direct_permit", False)
    context.setdefault("execution_phase", "confirm")
    context.setdefault("preview_confirmed", True)
    return context


async def _ensure_formal_security_schema(session: AsyncSession) -> None:
    """Verify formal-security tables exist for the current database engine.

    Runtime enforcement is read-only with respect to schema and must not perform
    any DDL. Missing formal tables are treated as an unrecoverable fail-closed
    condition for guarded operations.
    """
    connection = await session.connection()
    engine_key = id(connection.engine)
    if engine_key in _FORMAL_SCHEMA_READY:
        return

    def _missing_tables(sync_conn: Any) -> list[str]:
        inspector = inspect(sync_conn)
        existing = set(inspector.get_table_names())
        missing = sorted(_FORMAL_SECURITY_TABLE_NAMES.difference(existing))
        return missing

    async with _FORMAL_SCHEMA_LOCK:
        if engine_key in _FORMAL_SCHEMA_READY:
            return
        missing_tables = await connection.run_sync(_missing_tables)
        if missing_tables:
            raise RuntimeError(
                "Formal security schema is incomplete. Missing tables: "
                f"{', '.join(missing_tables)}. "
                "Run migrations before starting runtime pods."
            )
        _FORMAL_SCHEMA_READY.add(engine_key)


async def evaluate_action_admissibility(
    *,
    session: AsyncSession,
    principal: str,
    action: str,
    resource: str,
    runtime_context: dict[str, Any] | None,
    delegation_ref: str | None,
    tenant_id: str | None,
) -> EnforcementResult:
    """Evaluate action admissibility and return signed certificate."""
    alpha = AlphaContext.from_runtime(
        principal=principal,
        action=action,
        resource=resource,
        runtime_context=_normalize_runtime_context(runtime_context),
        delegation_ref=delegation_ref,
        tenant_id=tenant_id,
    )

    gamma_builder = GammaBuilder(session)
    gamma = await gamma_builder.build(alpha)
    certificate = evaluate_admissibility(alpha, gamma.gamma)

    return EnforcementResult(alpha=alpha, gamma=gamma, certificate=certificate)


async def enforce_action(
    *,
    principal: str,
    action: str,
    resource: str,
    runtime_context: dict[str, Any] | None = None,
    delegation_ref: str | None = None,
    tenant_id: str | None = None,
    chain_id: str = "global",
    session: AsyncSession | None = None,
) -> DecisionCertificate:
    """Enforce formal admissibility and persist signed evidence.

    Raises:
        SecurityEnforcementError: if decision evaluates to INADMISSIBLE.
    """

    async def _run(active_session: AsyncSession) -> DecisionCertificate:
        await _ensure_formal_security_schema(active_session)

        # Check honey-token deception before evaluation
        await _check_honey_tokens(
            active_session,
            action=action,
            resource=resource,
            principal=principal,
            delegation_ref=delegation_ref,
        )

        result = await evaluate_action_admissibility(
            session=active_session,
            principal=principal,
            action=action,
            resource=resource,
            runtime_context=runtime_context,
            delegation_ref=delegation_ref,
            tenant_id=tenant_id,
        )
        await _emit_runtime_solver_audit_events(
            active_session,
            alpha=result.alpha,
            certificate=result.certificate,
        )

        await append_decision_evidence(
            active_session,
            alpha=result.alpha,
            gamma_hash=result.gamma.gamma.gamma_hash or "",
            certificate=result.certificate,
            chain_id=chain_id,
        )

        # Transparency log (always runs, even single-node)
        await _append_transparency_log(
            active_session,
            result.certificate,
            result.alpha,
        )

        # Consensus verification (only if enabled)
        await _check_consensus(
            active_session,
            result.certificate,
            result.alpha,
            result.gamma.gamma,
        )

        if result.certificate.result == DecisionResult.INADMISSIBLE:
            raise SecurityEnforcementError(
                f"Action inadmissible: {action}",
                result.certificate,
            )

        return result.certificate

    if session is not None:
        return await _run(session)

    async with get_session_context() as scoped_session:
        return await _run(scoped_session)


async def _emit_runtime_solver_audit_events(
    session: AsyncSession,
    *,
    alpha: AlphaContext,
    certificate: DecisionCertificate,
) -> None:
    """Emit structured audit events for runtime solver drift and failures."""
    proof_payload = certificate.proof_payload
    if not isinstance(proof_payload, dict):
        return
    runtime_solver = proof_payload.get("runtime_solver")
    if not isinstance(runtime_solver, dict):
        return

    base_details = {
        "decision_id": str(certificate.decision_id),
        "principal": alpha.principal,
        "action": alpha.action,
        "resource": alpha.resource,
        "tenant_id": alpha.tenant_id,
        "solver_mode": runtime_solver.get("solver_mode"),
        "solver_backend": runtime_solver.get("solver_backend"),
        "z3_check_result": runtime_solver.get("z3_check_result"),
        "failure_reason": runtime_solver.get("failure_reason"),
        "drift_detected": bool(runtime_solver.get("drift_detected", False)),
    }

    if bool(runtime_solver.get("drift_detected", False)):
        await emit_audit_event(
            session,
            event_type="formal_solver_drift",
            actor=alpha.principal,
            tool=alpha.action,
            result="blocked",
            details=base_details,
        )

    if runtime_solver.get("z3_check_result") == "error":
        await emit_audit_event(
            session,
            event_type="formal_solver_error",
            actor=alpha.principal,
            tool=alpha.action,
            result="blocked",
            details=base_details,
        )


async def _check_honey_tokens(
    session: AsyncSession,
    *,
    action: str,
    resource: str,
    principal: str,
    delegation_ref: str | None,
) -> None:
    """Check action against honey-token registry and block if matched.

    Raises SecurityEnforcementError if action targets a canary resource.
    """
    tokens = await load_honey_tokens(session)
    if not tokens:
        return

    matched = check_action_against_tokens(action, resource, tokens)
    if matched is None:
        return

    alpha = AlphaContext.from_runtime(
        principal=principal,
        action=action,
        resource=resource,
        runtime_context={"deception_check": True},
        delegation_ref=delegation_ref,
    )

    severity = determine_severity(matched, alpha)
    severity_to_trust = {
        1: TrustDegradation.FLAG_ONLY,
        2: TrustDegradation.DOWNGRADE_TRUST,
        3: TrustDegradation.SUSPEND_GRANTS,
    }
    level = severity_to_trust.get(
        min(severity, 3),
        TrustDegradation.FLAG_ONLY,
    )
    trigger = await record_deception_trigger(
        session,
        token=matched,
        alpha=alpha,
        delegation_chain_ids=([delegation_ref] if delegation_ref else []),
        trust_action=level,
    )
    await apply_trust_degradation(session, trigger, level)

    logger.critical(
        "Honey-token triggered: token=%s principal=%s action=%s resource=%s severity=%d",
        matched.name,
        principal,
        action,
        resource,
        severity,
    )

    # Build a minimal inadmissible certificate for the error
    cert = DecisionCertificate(
        theorem_hash=theorem_hash_for_expression(THEOREM_EXPRESSION),
        result=DecisionResult.INADMISSIBLE,
        proof_type=ProofType.COUNTEREXAMPLE,
        proof_payload={
            "counterexample": {
                "predicate": "DECEPTION_TRIGGER",
                "witness": {
                    "token_name": matched.name,
                    "trigger_id": trigger.trigger_id,
                },
            },
        },
        alpha_hash=sha256_hex(canonical_json({"principal": principal})),
        gamma_hash=sha256_hex("honey-token-block"),
    )
    cert.sign(load_private_key())
    raise SecurityEnforcementError(
        f"Action blocked: honey-token triggered ({matched.name})",
        cert,
    )


async def _append_transparency_log(
    session: AsyncSession,
    certificate: DecisionCertificate,
    alpha: AlphaContext,
) -> None:
    """Append decision to transparency log (always runs)."""
    _ = alpha
    try:
        consensus_verifier = import_module("server.policy_governance.kernel.consensus_verifier")
        append_to_transparency_log = getattr(consensus_verifier, "append_to_transparency_log")

        await append_to_transparency_log(
            session,
            certificate,
            alpha_hash=certificate.alpha_hash,
            gamma_hash=certificate.gamma_hash,
        )
    except (AttributeError, ImportError, OSError, RuntimeError, ValueError):
        logger.debug(
            "Transparency log append skipped (not configured)",
            exc_info=True,
        )


async def _check_consensus(
    session: AsyncSession,
    certificate: DecisionCertificate,
    alpha: AlphaContext,
    gamma: Any,
) -> None:
    """Run consensus verification if enabled."""
    try:
        consensus_verifier = import_module("server.policy_governance.kernel.consensus_verifier")
        load_consensus_config = getattr(consensus_verifier, "_load_consensus_config")
        broadcast_global_revocation = getattr(consensus_verifier, "broadcast_global_revocation")
        collect_quorum = getattr(consensus_verifier, "collect_quorum")

        config = load_consensus_config()
        if not config.enabled:
            return
        if config.quorum_threshold <= 1:
            return

        result = await collect_quorum(
            session,
            certificate,
            alpha,
            gamma,
            config,
        )
        if result.global_revocation:
            await broadcast_global_revocation(
                session,
                str(certificate.decision_id),
                result.revocation_reason or "Consensus INADMISSIBLE",
                config,
            )

            if certificate.result == DecisionResult.ADMISSIBLE:
                raise SecurityEnforcementError(
                    "Consensus revocation: remote node disagreed",
                    certificate,
                )
        if not result.quorum_reached:
            logger.warning(
                "Consensus quorum not reached: %d/%d signatures",
                result.signatures_collected,
                result.required,
            )
    except SecurityEnforcementError:
        raise
    except (AttributeError, ImportError, OSError, RuntimeError, ValueError):
        logger.debug(
            "Consensus check skipped",
            exc_info=True,
        )
