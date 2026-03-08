"""Add formal delegation and proof-carrying enforcement tables.

Revision ID: 20260211_0001
Revises:
Create Date: 2026-02-11 03:00:00
"""

from __future__ import annotations

import importlib
from typing import Any, Sequence

import sqlalchemy as sa


op: Any = importlib.import_module("alembic.op")

REVISION: str = "20260211_0001"
DOWN_REVISION: str | None = None
BRANCH_LABELS: Sequence[str] | None = None
DEPENDS_ON: Sequence[str] | None = None

globals()["revision"] = REVISION
globals()["down_revision"] = DOWN_REVISION
globals()["branch_labels"] = BRANCH_LABELS
globals()["depends_on"] = DEPENDS_ON


def _table_exists(table_name: str) -> bool:
    """Return True when the table is already present."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return table_name in inspector.get_table_names()


def _create_delegation_grants(users_table_exists: bool) -> None:
    """Create delegation grant storage and supporting indexes."""
    delegation_grants_columns: list[sa.SchemaItem] = [
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("grant_id", sa.String(length=64), nullable=False),
        sa.Column("principal", sa.String(length=255), nullable=False),
        sa.Column("delegate", sa.String(length=255), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("parent_grant_id", sa.String(length=64), nullable=True),
        sa.Column("hop_index", sa.Integer(), nullable=False),
        sa.Column("allowed_actions", sa.JSON(), nullable=False),
        sa.Column("resource_scope", sa.String(length=1024), nullable=False),
        sa.Column("obligations", sa.JSON(), nullable=False),
        sa.Column("context_constraints", sa.JSON(), nullable=False),
        sa.Column("signature", sa.String(length=512), nullable=False),
        sa.Column("issued_by_user_id", sa.Integer(), nullable=True),
        sa.Column("issued_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
    ]
    if users_table_exists:
        delegation_grants_columns.append(
            sa.ForeignKeyConstraint(["issued_by_user_id"], ["users.id"])
        )
    delegation_grants_columns.append(sa.PrimaryKeyConstraint("id"))
    op.create_table("delegation_grants", *delegation_grants_columns)
    op.create_index(
        op.f("ix_delegation_grants_delegate"), "delegation_grants", ["delegate"], unique=False
    )
    op.create_index(
        op.f("ix_delegation_grants_expires_at"), "delegation_grants", ["expires_at"], unique=False
    )
    op.create_index(
        op.f("ix_delegation_grants_grant_id"), "delegation_grants", ["grant_id"], unique=True
    )
    op.create_index(
        op.f("ix_delegation_grants_parent_grant_id"),
        "delegation_grants",
        ["parent_grant_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_delegation_grants_principal"), "delegation_grants", ["principal"], unique=False
    )
    op.create_index(
        op.f("ix_delegation_grants_revoked"), "delegation_grants", ["revoked"], unique=False
    )
    op.create_index(
        op.f("ix_delegation_grants_tenant_id"), "delegation_grants", ["tenant_id"], unique=False
    )
    op.create_index(
        "ix_delegation_grants_principal_expiry_revoked",
        "delegation_grants",
        ["principal", "expires_at", "revoked"],
        unique=False,
    )


def _create_delegation_revocations(users_table_exists: bool) -> None:
    """Create delegation revocation storage and supporting indexes."""
    delegation_revocation_columns: list[sa.SchemaItem] = [
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("revocation_id", sa.String(length=64), nullable=False),
        sa.Column("grant_id", sa.String(length=64), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("revoked_by_user_id", sa.Integer(), nullable=True),
        sa.Column("reason", sa.String(length=1024), nullable=False),
        sa.Column("transitive", sa.Boolean(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=False),
    ]
    if users_table_exists:
        delegation_revocation_columns.append(
            sa.ForeignKeyConstraint(["revoked_by_user_id"], ["users.id"])
        )
    delegation_revocation_columns.append(sa.PrimaryKeyConstraint("id"))
    op.create_table("delegation_revocations", *delegation_revocation_columns)
    op.create_index(
        op.f("ix_delegation_revocations_grant_id"),
        "delegation_revocations",
        ["grant_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_delegation_revocations_revocation_id"),
        "delegation_revocations",
        ["revocation_id"],
        unique=True,
    )
    op.create_index(
        op.f("ix_delegation_revocations_revoked_at"),
        "delegation_revocations",
        ["revoked_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_delegation_revocations_tenant_id"),
        "delegation_revocations",
        ["tenant_id"],
        unique=False,
    )


def _create_decision_certificates() -> None:
    """Create persisted proof certificate storage and indexes."""
    op.create_table(
        "decision_certificates",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("decision_id", sa.String(length=64), nullable=False),
        sa.Column("theorem_hash", sa.String(length=64), nullable=False),
        sa.Column("result", sa.String(length=32), nullable=False),
        sa.Column("proof_type", sa.String(length=64), nullable=False),
        sa.Column("alpha_hash", sa.String(length=64), nullable=False),
        sa.Column("gamma_hash", sa.String(length=64), nullable=False),
        sa.Column("principal", sa.String(length=255), nullable=False),
        sa.Column("action", sa.String(length=255), nullable=False),
        sa.Column("resource", sa.String(length=1024), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=True),
        sa.Column("solver_version", sa.String(length=128), nullable=False),
        sa.Column("proof_payload", sa.JSON(), nullable=False),
        sa.Column("signature", sa.String(length=1024), nullable=False),
        sa.Column("certificate_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_decision_certificates_action"), "decision_certificates", ["action"], unique=False
    )
    op.create_index(
        op.f("ix_decision_certificates_alpha_hash"),
        "decision_certificates",
        ["alpha_hash"],
        unique=False,
    )
    op.create_index(
        op.f("ix_decision_certificates_created_at"),
        "decision_certificates",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_decision_certificates_decision_id"),
        "decision_certificates",
        ["decision_id"],
        unique=True,
    )
    op.create_index(
        op.f("ix_decision_certificates_gamma_hash"),
        "decision_certificates",
        ["gamma_hash"],
        unique=False,
    )
    op.create_index(
        op.f("ix_decision_certificates_principal"),
        "decision_certificates",
        ["principal"],
        unique=False,
    )
    op.create_index(
        op.f("ix_decision_certificates_result"), "decision_certificates", ["result"], unique=False
    )
    op.create_index(
        op.f("ix_decision_certificates_tenant_id"),
        "decision_certificates",
        ["tenant_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_decision_certificates_theorem_hash"),
        "decision_certificates",
        ["theorem_hash"],
        unique=False,
    )
    op.create_index(
        "ix_decision_certificates_decision_theorem",
        "decision_certificates",
        ["decision_id", "theorem_hash"],
        unique=False,
    )


def _create_execution_evidence_chain() -> None:
    """Create evidence chain storage and supporting indexes."""
    op.create_table(
        "execution_evidence_chain",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("chain_id", sa.String(length=128), nullable=False),
        sa.Column("hop_index", sa.Integer(), nullable=False),
        sa.Column("decision_id", sa.String(length=64), nullable=False),
        sa.Column("previous_hash", sa.String(length=64), nullable=True),
        sa.Column("current_hash", sa.String(length=64), nullable=False),
        sa.Column("payload_hash", sa.String(length=64), nullable=False),
        sa.Column("payload_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("chain_id", "hop_index", name="uq_execution_evidence_chain_chain_hop"),
    )
    op.create_index(
        op.f("ix_execution_evidence_chain_chain_id"),
        "execution_evidence_chain",
        ["chain_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_execution_evidence_chain_current_hash"),
        "execution_evidence_chain",
        ["current_hash"],
        unique=True,
    )
    op.create_index(
        op.f("ix_execution_evidence_chain_created_at"),
        "execution_evidence_chain",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_execution_evidence_chain_decision_id"),
        "execution_evidence_chain",
        ["decision_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_execution_evidence_chain_hop_index"),
        "execution_evidence_chain",
        ["hop_index"],
        unique=False,
    )


def upgrade() -> None:
    """Apply formal security schema changes."""
    # Existing deployments may already include these tables via SQLModel metadata
    # initialization before Alembic version tracking was introduced.
    if _table_exists("delegation_grants"):
        return

    users_table_exists = _table_exists("users")
    _create_delegation_grants(users_table_exists)
    _create_delegation_revocations(users_table_exists)
    _create_decision_certificates()
    _create_execution_evidence_chain()
    op.create_index(
        op.f("ix_execution_evidence_chain_previous_hash"),
        "execution_evidence_chain",
        ["previous_hash"],
        unique=False,
    )

    op.create_table(
        "counterexample_traces",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("trace_id", sa.String(length=64), nullable=False),
        sa.Column("decision_id", sa.String(length=64), nullable=False),
        sa.Column("chain_id", sa.String(length=128), nullable=False),
        sa.Column("hop_index", sa.Integer(), nullable=False),
        sa.Column("violation_class", sa.String(length=128), nullable=False),
        sa.Column("step_action", sa.String(length=255), nullable=False),
        sa.Column("step_resource", sa.String(length=1024), nullable=False),
        sa.Column("trace_payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("chain_id", "hop_index", name="uq_counterexample_chain_hop"),
    )
    op.create_index(
        op.f("ix_counterexample_traces_chain_id"),
        "counterexample_traces",
        ["chain_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_counterexample_traces_created_at"),
        "counterexample_traces",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_counterexample_traces_decision_id"),
        "counterexample_traces",
        ["decision_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_counterexample_traces_hop_index"),
        "counterexample_traces",
        ["hop_index"],
        unique=False,
    )
    op.create_index(
        op.f("ix_counterexample_traces_trace_id"),
        "counterexample_traces",
        ["trace_id"],
        unique=True,
    )
    op.create_index(
        op.f("ix_counterexample_traces_violation_class"),
        "counterexample_traces",
        ["violation_class"],
        unique=False,
    )

    op.create_table(
        "proof_verification_runs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("decision_id", sa.String(length=64), nullable=False),
        sa.Column("theorem_hash", sa.String(length=64), nullable=False),
        sa.Column("gamma_hash", sa.String(length=64), nullable=False),
        sa.Column("alpha_hash", sa.String(length=64), nullable=False),
        sa.Column("verification_result", sa.Boolean(), nullable=False),
        sa.Column("verifier_version", sa.String(length=128), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("checked_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_proof_verification_runs_alpha_hash"),
        "proof_verification_runs",
        ["alpha_hash"],
        unique=False,
    )
    op.create_index(
        op.f("ix_proof_verification_runs_checked_at"),
        "proof_verification_runs",
        ["checked_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_proof_verification_runs_decision_id"),
        "proof_verification_runs",
        ["decision_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_proof_verification_runs_gamma_hash"),
        "proof_verification_runs",
        ["gamma_hash"],
        unique=False,
    )
    op.create_index(
        op.f("ix_proof_verification_runs_run_id"),
        "proof_verification_runs",
        ["run_id"],
        unique=True,
    )
    op.create_index(
        op.f("ix_proof_verification_runs_theorem_hash"),
        "proof_verification_runs",
        ["theorem_hash"],
        unique=False,
    )
    op.create_index(
        op.f("ix_proof_verification_runs_verification_result"),
        "proof_verification_runs",
        ["verification_result"],
        unique=False,
    )


def downgrade() -> None:
    """Revert formal security schema changes."""
    op.drop_index(
        op.f("ix_proof_verification_runs_verification_result"), table_name="proof_verification_runs"
    )
    op.drop_index(
        op.f("ix_proof_verification_runs_theorem_hash"), table_name="proof_verification_runs"
    )
    op.drop_index(op.f("ix_proof_verification_runs_run_id"), table_name="proof_verification_runs")
    op.drop_index(
        op.f("ix_proof_verification_runs_gamma_hash"), table_name="proof_verification_runs"
    )
    op.drop_index(
        op.f("ix_proof_verification_runs_decision_id"), table_name="proof_verification_runs"
    )
    op.drop_index(
        op.f("ix_proof_verification_runs_checked_at"), table_name="proof_verification_runs"
    )
    op.drop_index(
        op.f("ix_proof_verification_runs_alpha_hash"), table_name="proof_verification_runs"
    )
    op.drop_table("proof_verification_runs")

    op.drop_index(
        op.f("ix_counterexample_traces_violation_class"), table_name="counterexample_traces"
    )
    op.drop_index(op.f("ix_counterexample_traces_trace_id"), table_name="counterexample_traces")
    op.drop_index(op.f("ix_counterexample_traces_hop_index"), table_name="counterexample_traces")
    op.drop_index(op.f("ix_counterexample_traces_decision_id"), table_name="counterexample_traces")
    op.drop_index(op.f("ix_counterexample_traces_created_at"), table_name="counterexample_traces")
    op.drop_index(op.f("ix_counterexample_traces_chain_id"), table_name="counterexample_traces")
    op.drop_table("counterexample_traces")

    op.drop_index(
        op.f("ix_execution_evidence_chain_previous_hash"), table_name="execution_evidence_chain"
    )
    op.drop_index(
        op.f("ix_execution_evidence_chain_hop_index"), table_name="execution_evidence_chain"
    )
    op.drop_index(
        op.f("ix_execution_evidence_chain_decision_id"), table_name="execution_evidence_chain"
    )
    op.drop_index(
        op.f("ix_execution_evidence_chain_created_at"), table_name="execution_evidence_chain"
    )
    op.drop_index(
        op.f("ix_execution_evidence_chain_current_hash"), table_name="execution_evidence_chain"
    )
    op.drop_index(
        op.f("ix_execution_evidence_chain_chain_id"), table_name="execution_evidence_chain"
    )
    op.drop_table("execution_evidence_chain")

    op.drop_index("ix_decision_certificates_decision_theorem", table_name="decision_certificates")
    op.drop_index(op.f("ix_decision_certificates_theorem_hash"), table_name="decision_certificates")
    op.drop_index(op.f("ix_decision_certificates_tenant_id"), table_name="decision_certificates")
    op.drop_index(op.f("ix_decision_certificates_result"), table_name="decision_certificates")
    op.drop_index(op.f("ix_decision_certificates_principal"), table_name="decision_certificates")
    op.drop_index(op.f("ix_decision_certificates_gamma_hash"), table_name="decision_certificates")
    op.drop_index(op.f("ix_decision_certificates_decision_id"), table_name="decision_certificates")
    op.drop_index(op.f("ix_decision_certificates_created_at"), table_name="decision_certificates")
    op.drop_index(op.f("ix_decision_certificates_alpha_hash"), table_name="decision_certificates")
    op.drop_index(op.f("ix_decision_certificates_action"), table_name="decision_certificates")
    op.drop_table("decision_certificates")

    op.drop_index(op.f("ix_delegation_revocations_tenant_id"), table_name="delegation_revocations")
    op.drop_index(op.f("ix_delegation_revocations_revoked_at"), table_name="delegation_revocations")
    op.drop_index(
        op.f("ix_delegation_revocations_revocation_id"), table_name="delegation_revocations"
    )
    op.drop_index(op.f("ix_delegation_revocations_grant_id"), table_name="delegation_revocations")
    op.drop_table("delegation_revocations")

    op.drop_index("ix_delegation_grants_principal_expiry_revoked", table_name="delegation_grants")
    op.drop_index(op.f("ix_delegation_grants_tenant_id"), table_name="delegation_grants")
    op.drop_index(op.f("ix_delegation_grants_revoked"), table_name="delegation_grants")
    op.drop_index(op.f("ix_delegation_grants_principal"), table_name="delegation_grants")
    op.drop_index(op.f("ix_delegation_grants_parent_grant_id"), table_name="delegation_grants")
    op.drop_index(op.f("ix_delegation_grants_grant_id"), table_name="delegation_grants")
    op.drop_index(op.f("ix_delegation_grants_expires_at"), table_name="delegation_grants")
    op.drop_index(op.f("ix_delegation_grants_delegate"), table_name="delegation_grants")
    op.drop_table("delegation_grants")
