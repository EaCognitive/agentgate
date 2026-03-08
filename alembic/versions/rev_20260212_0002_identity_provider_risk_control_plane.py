"""Add identity provider, risk policy, and verification grant tables.

Revision ID: 20260212_0002
Revises: 20260211_0001
Create Date: 2026-02-12 09:00:00
"""

from __future__ import annotations

import importlib
from typing import Any, Sequence

import sqlalchemy as sa


op: Any = importlib.import_module("alembic.op")

REVISION: str = "20260212_0002"
DOWN_REVISION: str | None = "20260211_0001"
BRANCH_LABELS: Sequence[str] | None = None
DEPENDS_ON: Sequence[str] | None = None

globals()["revision"] = REVISION
globals()["down_revision"] = DOWN_REVISION
globals()["branch_labels"] = BRANCH_LABELS
globals()["depends_on"] = DEPENDS_ON


def _table_exists(table_name: str) -> bool:
    """Return True when table exists in the current schema."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return table_name in inspector.get_table_names()


def _column_exists(table_name: str, column_name: str) -> bool:
    """Return True when table/column exists."""
    if not _table_exists(table_name):
        return False
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return any(column["name"] == column_name for column in inspector.get_columns(table_name))


def _index_exists(table_name: str, index_name: str) -> bool:
    """Return True when index already exists."""
    if not _table_exists(table_name):
        return False
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return any(index["name"] == index_name for index in inspector.get_indexes(table_name))


def _add_column_if_missing(table_name: str, column: sa.Column) -> None:
    """Add a column only when the target table and column state requires it."""
    if _table_exists(table_name) and not _column_exists(table_name, column.name):
        op.add_column(table_name, column)


def _create_index_if_missing(
    index_name: str,
    table_name: str,
    columns: list[str],
    *,
    unique: bool = False,
) -> None:
    """Create index only when table exists and index is absent."""
    if _table_exists(table_name) and not _index_exists(table_name, index_name):
        op.create_index(index_name, table_name, columns, unique=unique)


def _upgrade_users_identity_columns() -> None:
    """Add identity-provider fields to the users table when missing."""
    _add_column_if_missing("users", sa.Column("principal_id", sa.String(length=64), nullable=True))
    _add_column_if_missing(
        "users",
        sa.Column(
            "identity_provider",
            sa.String(length=64),
            nullable=False,
            server_default="local",
        ),
    )
    _add_column_if_missing(
        "users", sa.Column("provider_subject", sa.String(length=255), nullable=True)
    )
    _add_column_if_missing(
        "users",
        sa.Column("tenant_id", sa.String(length=128), nullable=False, server_default="default"),
    )
    _create_index_if_missing(op.f("ix_users_principal_id"), "users", ["principal_id"], unique=False)
    _create_index_if_missing(
        op.f("ix_users_identity_provider"), "users", ["identity_provider"], unique=False
    )
    _create_index_if_missing(
        op.f("ix_users_provider_subject"), "users", ["provider_subject"], unique=False
    )
    _create_index_if_missing(op.f("ix_users_tenant_id"), "users", ["tenant_id"], unique=False)


def _upgrade_pii_session_identity_columns() -> None:
    """Add tenant and identity-scoping columns to PII sessions when missing."""
    _add_column_if_missing(
        "pii_sessions",
        sa.Column("tenant_id", sa.String(length=128), nullable=False, server_default="default"),
    )
    _add_column_if_missing(
        "pii_sessions", sa.Column("principal_id", sa.String(length=64), nullable=True)
    )
    _add_column_if_missing(
        "pii_sessions", sa.Column("channel_id", sa.String(length=120), nullable=True)
    )
    _add_column_if_missing(
        "pii_sessions", sa.Column("conversation_id", sa.String(length=255), nullable=True)
    )
    _add_column_if_missing(
        "pii_sessions",
        sa.Column(
            "obligation_profile",
            sa.String(length=64),
            nullable=False,
            server_default="strict_tokenized",
        ),
    )
    _add_column_if_missing(
        "pii_sessions",
        sa.Column("authorized_viewers", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )
    _create_index_if_missing(
        op.f("ix_pii_sessions_tenant_id"), "pii_sessions", ["tenant_id"], unique=False
    )
    _create_index_if_missing(
        op.f("ix_pii_sessions_principal_id"), "pii_sessions", ["principal_id"], unique=False
    )
    _create_index_if_missing(
        op.f("ix_pii_sessions_channel_id"), "pii_sessions", ["channel_id"], unique=False
    )
    _create_index_if_missing(
        op.f("ix_pii_sessions_conversation_id"),
        "pii_sessions",
        ["conversation_id"],
        unique=False,
    )


def _create_identity_principals() -> None:
    """Create identity principal storage and indexes."""
    op.create_table(
        "identity_principals",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("principal_id", sa.String(length=64), nullable=False),
        sa.Column("principal_type", sa.String(length=32), nullable=False),
        sa.Column("subject_id", sa.String(length=255), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("provider_subject", sa.String(length=255), nullable=True),
        sa.Column("display_name", sa.String(length=255), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_identity_principal_subject_tenant",
        "identity_principals",
        ["subject_id", "tenant_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_identity_principals_principal_id"),
        "identity_principals",
        ["principal_id"],
        unique=True,
    )
    op.create_index(
        op.f("ix_identity_principals_principal_type"),
        "identity_principals",
        ["principal_type"],
        unique=False,
    )
    op.create_index(
        op.f("ix_identity_principals_subject_id"),
        "identity_principals",
        ["subject_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_identity_principals_tenant_id"),
        "identity_principals",
        ["tenant_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_identity_principals_provider"),
        "identity_principals",
        ["provider"],
        unique=False,
    )
    op.create_index(
        op.f("ix_identity_principals_provider_subject"),
        "identity_principals",
        ["provider_subject"],
        unique=False,
    )
    op.create_index(
        op.f("ix_identity_principals_is_active"),
        "identity_principals",
        ["is_active"],
        unique=False,
    )
    op.create_index(
        op.f("ix_identity_principals_created_at"),
        "identity_principals",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_identity_principals_updated_at"),
        "identity_principals",
        ["updated_at"],
        unique=False,
    )


def _create_identity_links(users_table_exists: bool) -> None:
    """Create identity link mapping table and indexes."""
    identity_links_columns: list[sa.SchemaItem] = [
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("provider_subject", sa.String(length=255), nullable=False),
        sa.Column("principal_id", sa.String(length=64), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "provider",
            "provider_subject",
            "tenant_id",
            name="uq_identity_links_provider_subject_tenant",
        ),
    ]
    if users_table_exists:
        identity_links_columns.append(sa.ForeignKeyConstraint(["user_id"], ["users.id"]))
    op.create_table("identity_links", *identity_links_columns)
    op.create_index(
        op.f("ix_identity_links_provider"), "identity_links", ["provider"], unique=False
    )
    op.create_index(
        op.f("ix_identity_links_provider_subject"),
        "identity_links",
        ["provider_subject"],
        unique=False,
    )
    op.create_index(
        op.f("ix_identity_links_principal_id"),
        "identity_links",
        ["principal_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_identity_links_tenant_id"), "identity_links", ["tenant_id"], unique=False
    )
    op.create_index(op.f("ix_identity_links_user_id"), "identity_links", ["user_id"], unique=False)
    op.create_index(
        op.f("ix_identity_links_created_at"), "identity_links", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_identity_links_last_seen_at"), "identity_links", ["last_seen_at"], unique=False
    )


def _create_role_bindings(users_table_exists: bool) -> None:
    """Create principal role binding storage and indexes."""
    role_bindings_columns: list[sa.SchemaItem] = [
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("principal_id", sa.String(length=64), nullable=False),
        sa.Column("role", sa.String(length=64), nullable=False),
        sa.Column("scope_type", sa.String(length=32), nullable=False),
        sa.Column("scope_id", sa.String(length=255), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("created_by_user_id", sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "principal_id",
            "role",
            "scope_type",
            "scope_id",
            name="uq_role_bindings_principal_role_scope",
        ),
    ]
    if users_table_exists:
        role_bindings_columns.append(sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"]))
    op.create_table("role_bindings", *role_bindings_columns)
    op.create_index(
        op.f("ix_role_bindings_principal_id"), "role_bindings", ["principal_id"], unique=False
    )
    op.create_index(op.f("ix_role_bindings_role"), "role_bindings", ["role"], unique=False)
    op.create_index(
        op.f("ix_role_bindings_scope_type"), "role_bindings", ["scope_type"], unique=False
    )
    op.create_index(op.f("ix_role_bindings_scope_id"), "role_bindings", ["scope_id"], unique=False)
    op.create_index(
        op.f("ix_role_bindings_created_at"), "role_bindings", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_role_bindings_expires_at"), "role_bindings", ["expires_at"], unique=False
    )


def _create_risk_profiles() -> None:
    """Create risk profile storage and indexes."""
    op.create_table(
        "risk_profiles",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("principal_id", sa.String(length=64), nullable=False),
        sa.Column("principal_type", sa.String(length=32), nullable=False),
        sa.Column("risk_level", sa.String(length=4), nullable=False),
        sa.Column("reason", sa.String(length=1024), nullable=True),
        sa.Column("reviewed_by", sa.String(length=255), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_risk_profiles_principal_id"), "risk_profiles", ["principal_id"], unique=True
    )
    op.create_index(
        op.f("ix_risk_profiles_principal_type"), "risk_profiles", ["principal_type"], unique=False
    )
    op.create_index(
        op.f("ix_risk_profiles_risk_level"), "risk_profiles", ["risk_level"], unique=False
    )
    op.create_index(
        op.f("ix_risk_profiles_created_at"), "risk_profiles", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_risk_profiles_updated_at"), "risk_profiles", ["updated_at"], unique=False
    )


def _create_session_assurance_events() -> None:
    """Create session assurance event storage and indexes."""
    op.create_table(
        "session_assurance_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("event_id", sa.String(length=64), nullable=False),
        sa.Column("principal_id", sa.String(length=64), nullable=False),
        sa.Column("session_id", sa.String(length=255), nullable=True),
        sa.Column("assurance_level", sa.String(length=4), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=True),
        sa.Column("method", sa.String(length=64), nullable=True),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_session_assurance_events_event_id"),
        "session_assurance_events",
        ["event_id"],
        unique=True,
    )
    op.create_index(
        op.f("ix_session_assurance_events_principal_id"),
        "session_assurance_events",
        ["principal_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_session_assurance_events_session_id"),
        "session_assurance_events",
        ["session_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_session_assurance_events_assurance_level"),
        "session_assurance_events",
        ["assurance_level"],
        unique=False,
    )
    op.create_index(
        op.f("ix_session_assurance_events_event_type"),
        "session_assurance_events",
        ["event_type"],
        unique=False,
    )
    op.create_index(
        op.f("ix_session_assurance_events_created_at"),
        "session_assurance_events",
        ["created_at"],
        unique=False,
    )


def _create_policy_decisions() -> None:
    """Create policy decision audit storage and indexes."""
    op.create_table(
        "policy_decisions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("decision_id", sa.String(length=64), nullable=False),
        sa.Column("principal_id", sa.String(length=64), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("action", sa.String(length=255), nullable=False),
        sa.Column("resource", sa.String(length=1024), nullable=False),
        sa.Column("allowed", sa.Boolean(), nullable=False),
        sa.Column("reason", sa.String(length=1024), nullable=True),
        sa.Column("effective_risk", sa.String(length=4), nullable=False),
        sa.Column("required_assurance", sa.String(length=4), nullable=False),
        sa.Column("session_assurance", sa.String(length=4), nullable=False),
        sa.Column("required_step_up", sa.Boolean(), nullable=False),
        sa.Column("required_approval", sa.Boolean(), nullable=False),
        sa.Column("obligations_json", sa.JSON(), nullable=False),
        sa.Column("trace_id", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_policy_decisions_decision_id"), "policy_decisions", ["decision_id"], unique=True
    )
    op.create_index(
        op.f("ix_policy_decisions_principal_id"), "policy_decisions", ["principal_id"], unique=False
    )
    op.create_index(
        op.f("ix_policy_decisions_tenant_id"), "policy_decisions", ["tenant_id"], unique=False
    )
    op.create_index(
        op.f("ix_policy_decisions_action"), "policy_decisions", ["action"], unique=False
    )
    op.create_index(
        op.f("ix_policy_decisions_allowed"), "policy_decisions", ["allowed"], unique=False
    )
    op.create_index(
        op.f("ix_policy_decisions_effective_risk"),
        "policy_decisions",
        ["effective_risk"],
        unique=False,
    )
    op.create_index(
        op.f("ix_policy_decisions_trace_id"), "policy_decisions", ["trace_id"], unique=False
    )
    op.create_index(
        op.f("ix_policy_decisions_created_at"), "policy_decisions", ["created_at"], unique=False
    )
    op.create_index(
        "ix_policy_decision_principal_created",
        "policy_decisions",
        ["principal_id", "created_at"],
        unique=False,
    )


def _create_verification_grants(users_table_exists: bool) -> None:
    """Create verification grant storage and indexes."""
    verification_grants_columns: list[sa.SchemaItem] = [
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("grant_token", sa.String(length=256), nullable=False),
        sa.Column("principal_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("purpose", sa.String(length=255), nullable=False),
        sa.Column("risk_level", sa.String(length=4), nullable=False),
        sa.Column("required_assurance", sa.String(length=4), nullable=False),
        sa.Column("issued_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("used_at", sa.DateTime(), nullable=True),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    ]
    if users_table_exists:
        verification_grants_columns.append(sa.ForeignKeyConstraint(["user_id"], ["users.id"]))
    op.create_table("verification_grants", *verification_grants_columns)
    op.create_index(
        op.f("ix_verification_grants_grant_token"),
        "verification_grants",
        ["grant_token"],
        unique=True,
    )
    op.create_index(
        op.f("ix_verification_grants_principal_id"),
        "verification_grants",
        ["principal_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_verification_grants_user_id"), "verification_grants", ["user_id"], unique=False
    )
    op.create_index(
        op.f("ix_verification_grants_tenant_id"), "verification_grants", ["tenant_id"], unique=False
    )
    op.create_index(
        op.f("ix_verification_grants_purpose"), "verification_grants", ["purpose"], unique=False
    )
    op.create_index(
        op.f("ix_verification_grants_risk_level"),
        "verification_grants",
        ["risk_level"],
        unique=False,
    )
    op.create_index(
        op.f("ix_verification_grants_expires_at"),
        "verification_grants",
        ["expires_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_verification_grants_used_at"), "verification_grants", ["used_at"], unique=False
    )
    op.create_index(
        op.f("ix_verification_grants_revoked"), "verification_grants", ["revoked"], unique=False
    )


def _drop_indexes(table_name: str, *index_names: str) -> None:
    """Drop indexes for a table in the provided order."""
    for index_name in index_names:
        op.drop_index(index_name, table_name=table_name)


def _downgrade_verification_grants() -> None:
    """Drop verification grant indexes and table."""
    _drop_indexes(
        "verification_grants",
        op.f("ix_verification_grants_revoked"),
        op.f("ix_verification_grants_used_at"),
        op.f("ix_verification_grants_expires_at"),
        op.f("ix_verification_grants_risk_level"),
        op.f("ix_verification_grants_purpose"),
        op.f("ix_verification_grants_tenant_id"),
        op.f("ix_verification_grants_user_id"),
        op.f("ix_verification_grants_principal_id"),
        op.f("ix_verification_grants_grant_token"),
    )
    op.drop_table("verification_grants")


def _downgrade_policy_decisions() -> None:
    """Drop policy decision indexes and table."""
    _drop_indexes(
        "policy_decisions",
        "ix_policy_decision_principal_created",
        op.f("ix_policy_decisions_created_at"),
        op.f("ix_policy_decisions_trace_id"),
        op.f("ix_policy_decisions_effective_risk"),
        op.f("ix_policy_decisions_allowed"),
        op.f("ix_policy_decisions_action"),
        op.f("ix_policy_decisions_tenant_id"),
        op.f("ix_policy_decisions_principal_id"),
        op.f("ix_policy_decisions_decision_id"),
    )
    op.drop_table("policy_decisions")


def _downgrade_session_assurance_events() -> None:
    """Drop session assurance event indexes and table."""
    _drop_indexes(
        "session_assurance_events",
        op.f("ix_session_assurance_events_created_at"),
        op.f("ix_session_assurance_events_event_type"),
        op.f("ix_session_assurance_events_assurance_level"),
        op.f("ix_session_assurance_events_session_id"),
        op.f("ix_session_assurance_events_principal_id"),
        op.f("ix_session_assurance_events_event_id"),
    )
    op.drop_table("session_assurance_events")


def _downgrade_risk_profiles() -> None:
    """Drop risk profile indexes and table."""
    _drop_indexes(
        "risk_profiles",
        op.f("ix_risk_profiles_updated_at"),
        op.f("ix_risk_profiles_created_at"),
        op.f("ix_risk_profiles_risk_level"),
        op.f("ix_risk_profiles_principal_type"),
        op.f("ix_risk_profiles_principal_id"),
    )
    op.drop_table("risk_profiles")


def _downgrade_role_bindings() -> None:
    """Drop role binding indexes and table."""
    _drop_indexes(
        "role_bindings",
        op.f("ix_role_bindings_expires_at"),
        op.f("ix_role_bindings_created_at"),
        op.f("ix_role_bindings_scope_id"),
        op.f("ix_role_bindings_scope_type"),
        op.f("ix_role_bindings_role"),
        op.f("ix_role_bindings_principal_id"),
    )
    op.drop_table("role_bindings")


def _downgrade_identity_links() -> None:
    """Drop identity link indexes and table."""
    _drop_indexes(
        "identity_links",
        op.f("ix_identity_links_last_seen_at"),
        op.f("ix_identity_links_created_at"),
        op.f("ix_identity_links_user_id"),
        op.f("ix_identity_links_tenant_id"),
        op.f("ix_identity_links_principal_id"),
        op.f("ix_identity_links_provider_subject"),
        op.f("ix_identity_links_provider"),
    )
    op.drop_table("identity_links")


def _downgrade_identity_principals() -> None:
    """Drop identity principal indexes and table."""
    _drop_indexes(
        "identity_principals",
        op.f("ix_identity_principals_updated_at"),
        op.f("ix_identity_principals_created_at"),
        op.f("ix_identity_principals_is_active"),
        op.f("ix_identity_principals_provider_subject"),
        op.f("ix_identity_principals_provider"),
        op.f("ix_identity_principals_tenant_id"),
        op.f("ix_identity_principals_subject_id"),
        op.f("ix_identity_principals_principal_type"),
        op.f("ix_identity_principals_principal_id"),
        "ix_identity_principal_subject_tenant",
    )
    op.drop_table("identity_principals")


def _downgrade_pii_sessions() -> None:
    """Drop PII session identity columns and indexes."""
    _drop_indexes(
        "pii_sessions",
        op.f("ix_pii_sessions_conversation_id"),
        op.f("ix_pii_sessions_channel_id"),
        op.f("ix_pii_sessions_principal_id"),
        op.f("ix_pii_sessions_tenant_id"),
    )
    op.drop_column("pii_sessions", "authorized_viewers")
    op.drop_column("pii_sessions", "obligation_profile")
    op.drop_column("pii_sessions", "conversation_id")
    op.drop_column("pii_sessions", "channel_id")
    op.drop_column("pii_sessions", "principal_id")
    op.drop_column("pii_sessions", "tenant_id")


def _downgrade_users_identity_columns() -> None:
    """Drop user identity-provider columns and indexes."""
    _drop_indexes(
        "users",
        op.f("ix_users_tenant_id"),
        op.f("ix_users_provider_subject"),
        op.f("ix_users_identity_provider"),
        op.f("ix_users_principal_id"),
    )
    op.drop_column("users", "tenant_id")
    op.drop_column("users", "provider_subject")
    op.drop_column("users", "identity_provider")
    op.drop_column("users", "principal_id")


def upgrade() -> None:
    """Apply identity and risk control plane schema changes."""
    _upgrade_users_identity_columns()
    _upgrade_pii_session_identity_columns()

    # Legacy databases that were initialized via SQLModel metadata may already
    # include all identity/risk tables before Alembic versioning.
    if _table_exists("identity_principals"):
        return

    users_table_exists = _table_exists("users")
    _create_identity_principals()
    _create_identity_links(users_table_exists)
    _create_role_bindings(users_table_exists)
    _create_risk_profiles()
    _create_session_assurance_events()
    _create_policy_decisions()
    _create_verification_grants(users_table_exists)


def downgrade() -> None:
    """Revert identity and risk control plane schema changes."""
    _downgrade_verification_grants()
    _downgrade_policy_decisions()
    _downgrade_session_assurance_events()
    _downgrade_risk_profiles()
    _downgrade_role_bindings()
    _downgrade_identity_links()
    _downgrade_identity_principals()
    _downgrade_pii_sessions()
    _downgrade_users_identity_columns()
