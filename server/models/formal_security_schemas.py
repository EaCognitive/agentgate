"""Formal security and delegation persistence schemas.

These tables persist delegation lineage, signed decision certificates,
immutable evidence-chain records, and verification/counterexample artifacts.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, ClassVar

from sqlalchemy import Column, Index, JSON, UniqueConstraint
from sqlmodel import Field, SQLModel


def utc_now() -> datetime:
    """Return current UTC timestamp as timezone-naive database value."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class DelegationGrant(SQLModel, table=True):
    """Delegation grant linking principal authority to delegate scope."""

    __tablename__: ClassVar[str] = "delegation_grants"
    __table_args__ = (
        Index(
            "ix_delegation_grants_principal_expiry_revoked", "principal", "expires_at", "revoked"
        ),
    )

    id: int | None = Field(default=None, primary_key=True)
    grant_id: str = Field(index=True, unique=True, max_length=64)
    principal: str = Field(index=True, max_length=255)
    delegate: str = Field(index=True, max_length=255)
    tenant_id: str = Field(index=True, max_length=128)
    parent_grant_id: str | None = Field(default=None, index=True, max_length=64)
    hop_index: int = Field(default=0, ge=0)
    allowed_actions: list[str] = Field(sa_column=Column(JSON, nullable=False))
    resource_scope: str = Field(max_length=1024)
    obligations: dict[str, Any] = Field(
        default_factory=dict, sa_column=Column(JSON, nullable=False)
    )
    context_constraints: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    signature: str = Field(max_length=512)
    issued_by_user_id: int | None = Field(default=None, foreign_key="users.id")
    issued_at: datetime = Field(default_factory=utc_now, index=True)
    expires_at: datetime = Field(index=True)
    revoked: bool = Field(default=False, index=True)
    revoked_at: datetime | None = Field(default=None)


class DelegationRevocation(SQLModel, table=True):
    """Revocation record for delegation grants."""

    __tablename__: ClassVar[str] = "delegation_revocations"

    id: int | None = Field(default=None, primary_key=True)
    revocation_id: str = Field(index=True, unique=True, max_length=64)
    grant_id: str = Field(index=True, max_length=64)
    tenant_id: str = Field(index=True, max_length=128)
    revoked_by_user_id: int | None = Field(default=None, foreign_key="users.id")
    reason: str = Field(max_length=1024)
    transitive: bool = Field(default=True)
    revoked_at: datetime = Field(default_factory=utc_now, index=True)


class DecisionCertificateRecord(SQLModel, table=True):
    """Persisted signed certificate for each enforcement decision."""

    __tablename__: ClassVar[str] = "decision_certificates"
    __table_args__ = (
        Index("ix_decision_certificates_decision_theorem", "decision_id", "theorem_hash"),
    )

    id: int | None = Field(default=None, primary_key=True)
    decision_id: str = Field(index=True, unique=True, max_length=64)
    theorem_hash: str = Field(index=True, max_length=64)
    result: str = Field(index=True, max_length=32)
    proof_type: str = Field(max_length=64)
    alpha_hash: str = Field(index=True, max_length=64)
    gamma_hash: str = Field(index=True, max_length=64)
    principal: str = Field(index=True, max_length=255)
    action: str = Field(index=True, max_length=255)
    resource: str = Field(max_length=1024)
    tenant_id: str | None = Field(default=None, index=True, max_length=128)
    solver_version: str = Field(max_length=128)
    proof_payload: dict[str, Any] = Field(sa_column=Column(JSON, nullable=False))
    signature: str = Field(max_length=1024)
    certificate_json: dict[str, Any] = Field(sa_column=Column(JSON, nullable=False))
    created_at: datetime = Field(default_factory=utc_now, index=True)


class ExecutionEvidenceChain(SQLModel, table=True):
    """Immutable append-only evidence chain for decision payloads."""

    __tablename__: ClassVar[str] = "execution_evidence_chain"
    __table_args__ = (
        UniqueConstraint("chain_id", "hop_index", name="uq_execution_evidence_chain_chain_hop"),
    )

    id: int | None = Field(default=None, primary_key=True)
    chain_id: str = Field(index=True, max_length=128)
    hop_index: int = Field(index=True, ge=0)
    decision_id: str = Field(index=True, max_length=64)
    previous_hash: str | None = Field(default=None, index=True, max_length=64)
    current_hash: str = Field(index=True, unique=True, max_length=64)
    payload_hash: str = Field(max_length=64)
    payload_json: dict[str, Any] = Field(sa_column=Column(JSON, nullable=False))
    created_at: datetime = Field(default_factory=utc_now, index=True)


class CounterexampleTrace(SQLModel, table=True):
    """Persisted counterexample traces for blocked decisions."""

    __tablename__: ClassVar[str] = "counterexample_traces"
    __table_args__ = (
        UniqueConstraint("chain_id", "hop_index", name="uq_counterexample_chain_hop"),
    )

    id: int | None = Field(default=None, primary_key=True)
    trace_id: str = Field(index=True, unique=True, max_length=64)
    decision_id: str = Field(index=True, max_length=64)
    chain_id: str = Field(index=True, max_length=128)
    hop_index: int = Field(index=True, ge=0)
    violation_class: str = Field(index=True, max_length=128)
    step_action: str = Field(max_length=255)
    step_resource: str = Field(max_length=1024)
    trace_payload: dict[str, Any] = Field(sa_column=Column(JSON, nullable=False))
    created_at: datetime = Field(default_factory=utc_now, index=True)


class ProofVerificationRun(SQLModel, table=True):
    """Record of offline proof verification runs."""

    __tablename__: ClassVar[str] = "proof_verification_runs"

    id: int | None = Field(default=None, primary_key=True)
    run_id: str = Field(index=True, unique=True, max_length=64)
    decision_id: str = Field(index=True, max_length=64)
    theorem_hash: str = Field(index=True, max_length=64)
    gamma_hash: str = Field(index=True, max_length=64)
    alpha_hash: str = Field(index=True, max_length=64)
    verification_result: bool = Field(index=True)
    verifier_version: str = Field(max_length=128)
    details: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
    checked_at: datetime = Field(default_factory=utc_now, index=True)


class DelegationGrantRead(SQLModel):
    """Read model for delegation grants."""

    grant_id: str
    principal: str
    delegate: str
    tenant_id: str
    parent_grant_id: str | None
    hop_index: int
    allowed_actions: list[str]
    resource_scope: str
    obligations: dict[str, Any]
    context_constraints: dict[str, Any]
    issued_at: datetime
    expires_at: datetime
    revoked: bool


class DecisionCertificateRecordRead(SQLModel):
    """Read model for persisted decision certificates."""

    decision_id: str
    theorem_hash: str
    result: str
    proof_type: str
    alpha_hash: str
    gamma_hash: str
    solver_version: str
    signature: str
    created_at: datetime


class SynthesizedInvariantRecord(SQLModel, table=True):
    """Persisted synthesized policy invariants from fuzzing runs."""

    __tablename__: ClassVar[str] = "synthesized_invariants"
    __table_args__ = (
        Index("ix_synthesized_invariants_run_id", "run_id"),
        Index("ix_synthesized_invariants_type_status", "invariant_type", "status"),
    )

    id: int | None = Field(default=None, primary_key=True)
    invariant_id: str = Field(index=True, unique=True, max_length=64)
    run_id: str = Field(max_length=64)
    invariant_type: str = Field(index=True, max_length=64)
    description: str = Field(max_length=2048)
    dtsl_expression: str = Field(max_length=4096)
    alpha_sample: dict[str, Any] = Field(sa_column=Column(JSON, nullable=False))
    gamma_sample: dict[str, Any] = Field(sa_column=Column(JSON, nullable=False))
    confidence_score: float = Field(ge=0.0, le=1.0)
    status: str = Field(default="pending", index=True, max_length=32)
    created_at: datetime = Field(default_factory=utc_now, index=True)
    reviewed_at: datetime | None = Field(default=None)
    reviewed_by: str | None = Field(default=None, max_length=255)


class HoneyTokenRecord(SQLModel, table=True):
    """Honey token deception artifacts for malicious intent detection."""

    __tablename__: ClassVar[str] = "honey_tokens"
    __table_args__ = (Index("ix_honey_tokens_type_active", "token_type", "is_active"),)

    id: int | None = Field(default=None, primary_key=True)
    token_id: str = Field(index=True, unique=True, max_length=64)
    name: str = Field(max_length=255)
    token_type: str = Field(index=True, max_length=64)
    description: str = Field(max_length=2048)
    resource_pattern: str = Field(max_length=1024)
    trap_hash: str = Field(max_length=64)
    is_active: bool = Field(default=True, index=True)
    created_at: datetime = Field(default_factory=utc_now, index=True)
    created_by: str = Field(max_length=255)


class DeceptionTriggerRecord(SQLModel, table=True):
    """Records of honey token triggers and deception detection events."""

    __tablename__: ClassVar[str] = "deception_triggers"
    __table_args__ = (
        Index("ix_deception_triggers_principal_created", "principal", "created_at"),
        Index("ix_deception_triggers_token_severity", "token_id", "severity"),
    )

    id: int | None = Field(default=None, primary_key=True)
    trigger_id: str = Field(index=True, unique=True, max_length=64)
    token_id: str = Field(index=True, max_length=64)
    principal: str = Field(index=True, max_length=255)
    action: str = Field(max_length=255)
    resource: str = Field(max_length=1024)
    delegation_chain_ids: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    severity: int = Field(index=True)
    trust_action: str = Field(max_length=128)
    evidence_chain_id: str | None = Field(default=None, max_length=64)
    created_at: datetime = Field(default_factory=utc_now, index=True)


# ---------------------------------------------------------------------------
# Feature: Distributed Certificate Consensus
# ---------------------------------------------------------------------------


class SafetyNodeRecord(SQLModel, table=True):
    """Registered safety node for distributed consensus."""

    __tablename__: ClassVar[str] = "safety_nodes"

    id: int | None = Field(default=None, primary_key=True)
    node_id: str = Field(
        index=True,
        unique=True,
        max_length=64,
    )
    endpoint_url: str = Field(max_length=1024)
    public_key_pem: str = Field(max_length=4096)
    is_local: bool = Field(default=False)
    trust_score: float = Field(default=1.0)
    registered_at: datetime = Field(
        default_factory=utc_now,
        index=True,
    )
    last_seen_at: datetime | None = Field(default=None)


class TransparencyLogRecord(SQLModel, table=True):
    """Append-only transparency log for decision certificates."""

    __tablename__: ClassVar[str] = "transparency_log"

    id: int | None = Field(default=None, primary_key=True)
    log_index: int = Field(index=True, unique=True)
    decision_id: str = Field(index=True, max_length=64)
    certificate_hash: str = Field(max_length=64)
    alpha_hash: str = Field(max_length=64)
    gamma_hash: str = Field(max_length=64)
    result: str = Field(max_length=32)
    node_id: str = Field(default="local", max_length=64)
    created_at: datetime = Field(default_factory=utc_now, index=True)


class CoSignatureRecord(SQLModel, table=True):
    """Co-signature from a remote safety node."""

    __tablename__: ClassVar[str] = "co_signatures"

    id: int | None = Field(default=None, primary_key=True)
    cosig_id: str = Field(
        index=True,
        unique=True,
        max_length=64,
    )
    decision_id: str = Field(index=True, max_length=64)
    node_id: str = Field(index=True, max_length=64)
    signature: str = Field(max_length=1024)
    re_evaluation_result: str = Field(max_length=32)
    verified_at: datetime = Field(
        default_factory=utc_now,
        index=True,
    )


class GlobalRevocationRecord(SQLModel, table=True):
    """Global certificate revocation from consensus failure."""

    __tablename__: ClassVar[str] = "global_revocations"

    id: int | None = Field(default=None, primary_key=True)
    revocation_id: str = Field(
        index=True,
        unique=True,
        max_length=64,
    )
    decision_id: str = Field(index=True, max_length=64)
    reason: str = Field(max_length=2048)
    initiated_by_node_id: str = Field(max_length=64)
    revoked_at: datetime = Field(
        default_factory=utc_now,
        index=True,
    )
    acknowledged_by: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
