"""Immutable evidence chain persistence and offline verification routines."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import asc, desc
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import col, select

from server.models.formal_security_schemas import (
    CounterexampleTrace,
    DecisionCertificateRecord,
    ExecutionEvidenceChain,
    ProofVerificationRun,
)
from server.utils.db import commit as db_commit
from server.utils.db import execute as db_execute
from server.utils.db import rollback as db_rollback
from .formal_models import (
    AlphaContext,
    DecisionCertificate,
    canonical_json,
    load_private_key,
    sha256_hex,
)


MAX_CHAIN_APPEND_RETRIES = 5


@dataclass(slots=True)
class EvidenceChainStatus:
    """Verification status for a hash-linked evidence chain."""

    chain_id: str
    valid: bool
    checked_entries: int
    failure_reason: str | None = None
    failed_hop_index: int | None = None


def utc_now() -> datetime:
    """Return timezone-naive UTC timestamp for DB storage."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


async def append_decision_evidence(
    session: AsyncSession,
    *,
    alpha: AlphaContext,
    gamma_hash: str,
    certificate: DecisionCertificate,
    chain_id: str = "global",
) -> ExecutionEvidenceChain:
    """Persist decision certificate and append immutable evidence-chain entry."""
    payload_json = {
        "alpha": alpha.model_dump(mode="json"),
        "gamma_hash": gamma_hash,
        "certificate": certificate.model_dump(mode="json"),
    }
    payload_hash = sha256_hex(canonical_json(payload_json))

    for attempt in range(1, MAX_CHAIN_APPEND_RETRIES + 1):
        certificate_record = DecisionCertificateRecord(
            decision_id=str(certificate.decision_id),
            theorem_hash=certificate.theorem_hash,
            result=certificate.result.value,
            proof_type=certificate.proof_type.value,
            alpha_hash=certificate.alpha_hash,
            gamma_hash=certificate.gamma_hash,
            principal=alpha.principal,
            action=alpha.action,
            resource=alpha.resource,
            tenant_id=alpha.tenant_id,
            solver_version=certificate.solver_version,
            proof_payload=certificate.proof_payload,
            signature=certificate.signature or "",
            certificate_json=certificate.model_dump(mode="json"),
        )
        session.add(certificate_record)

        result = await db_execute(
            session,
            select(ExecutionEvidenceChain)
            .where(ExecutionEvidenceChain.chain_id == chain_id)
            .order_by(desc(col(ExecutionEvidenceChain.hop_index)))
            .limit(1),
        )
        previous = result.scalar_one_or_none()

        previous_hash = previous.current_hash if previous else None
        hop_index = (previous.hop_index + 1) if previous else 0
        current_hash = sha256_hex(f"{payload_hash}:{previous_hash or ''}")

        evidence = ExecutionEvidenceChain(
            chain_id=chain_id,
            hop_index=hop_index,
            decision_id=str(certificate.decision_id),
            previous_hash=previous_hash,
            current_hash=current_hash,
            payload_hash=payload_hash,
            payload_json=payload_json,
        )
        session.add(evidence)

        if certificate.proof_type.value == "COUNTEREXAMPLE":
            counterexample = certificate.proof_payload.get("counterexample", {})
            trace_entry = CounterexampleTrace(
                trace_id=f"cx_{uuid4().hex}",
                decision_id=str(certificate.decision_id),
                chain_id=f"{chain_id}:{certificate.decision_id}",
                hop_index=0,
                violation_class=str(counterexample.get("predicate", "unknown")),
                step_action=alpha.action,
                step_resource=alpha.resource,
                trace_payload=certificate.proof_payload,
            )
            session.add(trace_entry)

        try:
            await db_commit(session)
            return evidence
        except IntegrityError as exc:
            await db_rollback(session)
            session.expunge_all()
            if attempt == MAX_CHAIN_APPEND_RETRIES or "chain_id" not in str(exc):
                raise

    raise RuntimeError("evidence chain append retry budget exhausted")


async def verify_evidence_chain(
    session: AsyncSession,
    *,
    chain_id: str,
) -> EvidenceChainStatus:
    """Verify chain integrity by recomputing every hash-link in order."""
    result = await db_execute(
        session,
        select(ExecutionEvidenceChain)
        .where(ExecutionEvidenceChain.chain_id == chain_id)
        .order_by(asc(col(ExecutionEvidenceChain.hop_index))),
    )
    rows = result.scalars().all()

    previous_hash: str | None = None
    for row in rows:
        expected_payload_hash = sha256_hex(canonical_json(row.payload_json))
        if expected_payload_hash != row.payload_hash:
            return EvidenceChainStatus(
                chain_id=chain_id,
                valid=False,
                checked_entries=len(rows),
                failure_reason="Payload hash mismatch",
                failed_hop_index=row.hop_index,
            )

        expected_hash = sha256_hex(f"{row.payload_hash}:{previous_hash or ''}")
        if expected_hash != row.current_hash:
            return EvidenceChainStatus(
                chain_id=chain_id,
                valid=False,
                checked_entries=len(rows),
                failure_reason="Chain hash mismatch",
                failed_hop_index=row.hop_index,
            )

        if row.previous_hash != previous_hash:
            return EvidenceChainStatus(
                chain_id=chain_id,
                valid=False,
                checked_entries=len(rows),
                failure_reason="Previous hash linkage mismatch",
                failed_hop_index=row.hop_index,
            )

        previous_hash = row.current_hash

    return EvidenceChainStatus(
        chain_id=chain_id,
        valid=True,
        checked_entries=len(rows),
    )


async def verify_decision_certificate(
    session: AsyncSession,
    *,
    decision_id: str,
    verifier_version: str = "formal-verifier/v1",
) -> ProofVerificationRun:
    """Verify persisted certificate signature and theorem consistency."""
    result = await db_execute(
        session,
        select(DecisionCertificateRecord).where(
            DecisionCertificateRecord.decision_id == decision_id
        ),
    )
    record = result.scalar_one_or_none()
    if record is None:
        raise ValueError(f"Decision certificate not found: {decision_id}")

    certificate = DecisionCertificate.model_validate(record.certificate_json)
    public_key = load_private_key().public_key()
    signature_valid = certificate.verify(public_key)

    run = ProofVerificationRun(
        run_id=f"vr_{uuid4().hex}",
        decision_id=record.decision_id,
        theorem_hash=record.theorem_hash,
        gamma_hash=record.gamma_hash,
        alpha_hash=record.alpha_hash,
        verification_result=signature_valid,
        verifier_version=verifier_version,
        details={
            "signature_valid": signature_valid,
            "verified_at": utc_now().isoformat(),
        },
    )
    session.add(run)
    await db_commit(session)
    return run
