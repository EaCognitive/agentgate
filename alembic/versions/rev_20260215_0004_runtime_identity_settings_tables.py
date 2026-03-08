"""Add runtime identity and settings tables required by strict-profile readiness.

Revision ID: 20260215_0004
Revises: 20260215_0003
Create Date: 2026-02-15 13:15:00
"""

from __future__ import annotations

import importlib
from typing import Any, Sequence

import sqlalchemy as sa


op: Any = importlib.import_module("alembic.op")

REVISION: str = "20260215_0004"
DOWN_REVISION: str | None = "20260215_0003"
BRANCH_LABELS: Sequence[str] | None = None
DEPENDS_ON: Sequence[str] | None = None

globals()["revision"] = REVISION
globals()["down_revision"] = DOWN_REVISION
globals()["branch_labels"] = BRANCH_LABELS
globals()["depends_on"] = DEPENDS_ON


def _table_exists(table_name: str) -> bool:
    """Return True when table exists in the active database schema."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return table_name in inspector.get_table_names()


def _index_exists(table_name: str, index_name: str) -> bool:
    """Return True when index exists on the target table."""
    if not _table_exists(table_name):
        return False
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return any(index["name"] == index_name for index in inspector.get_indexes(table_name))


def _create_index_if_missing(
    index_name: str,
    table_name: str,
    columns: list[str],
    *,
    unique: bool = False,
) -> None:
    """Create an index only when it is absent."""
    if _index_exists(table_name, index_name):
        return
    op.create_index(index_name, table_name, columns, unique=unique)


def upgrade() -> None:
    """Apply runtime identity/settings compatibility tables."""
    users_table = "users"
    if not _table_exists(users_table):
        op.create_table(
            users_table,
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column("email", sa.String(length=255), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=True),
            sa.Column("role", sa.String(length=50), nullable=False, server_default="viewer"),
            sa.Column("hashed_password", sa.String(length=255), nullable=False),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column(
                "created_at",
                sa.DateTime(),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.Column("last_login", sa.DateTime(), nullable=True),
            sa.Column(
                "must_change_password",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            ),
            sa.Column("password_changed_at", sa.DateTime(), nullable=True),
            sa.Column(
                "is_default_credentials",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            ),
            sa.Column(
                "failed_login_attempts",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
            sa.Column("last_failed_login", sa.DateTime(), nullable=True),
            sa.Column("totp_secret", sa.String(length=512), nullable=True),
            sa.Column("totp_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("backup_codes", sa.JSON(), nullable=True),
            sa.Column("webauthn_credentials", sa.JSON(), nullable=True),
            sa.Column("principal_id", sa.String(length=64), nullable=True),
            sa.Column(
                "identity_provider",
                sa.String(length=64),
                nullable=False,
                server_default="local",
            ),
            sa.Column("provider_subject", sa.String(length=255), nullable=True),
            sa.Column(
                "tenant_id",
                sa.String(length=128),
                nullable=False,
                server_default="default",
            ),
            sa.UniqueConstraint("email", name=op.f("uq_users_email")),
        )

    _create_index_if_missing(op.f("ix_users_email"), users_table, ["email"])
    _create_index_if_missing(op.f("ix_users_principal_id"), users_table, ["principal_id"])
    _create_index_if_missing(op.f("ix_users_identity_provider"), users_table, ["identity_provider"])
    _create_index_if_missing(op.f("ix_users_provider_subject"), users_table, ["provider_subject"])
    _create_index_if_missing(op.f("ix_users_tenant_id"), users_table, ["tenant_id"])

    settings_table = "system_settings"
    if not _table_exists(settings_table):
        op.create_table(
            settings_table,
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column("key", sa.String(length=128), nullable=False),
            sa.Column("value", sa.JSON(), nullable=True),
            sa.Column(
                "updated_at",
                sa.DateTime(),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.UniqueConstraint("key", name=op.f("uq_system_settings_key")),
        )

    _create_index_if_missing(op.f("ix_system_settings_key"), settings_table, ["key"])


def downgrade() -> None:
    """Rollback runtime identity/settings compatibility tables."""
    settings_table = "system_settings"
    if _table_exists(settings_table):
        if _index_exists(settings_table, op.f("ix_system_settings_key")):
            op.drop_index(op.f("ix_system_settings_key"), table_name=settings_table)
        op.drop_table(settings_table)

    users_table = "users"
    if _table_exists(users_table):
        for index_name in (
            op.f("ix_users_tenant_id"),
            op.f("ix_users_provider_subject"),
            op.f("ix_users_identity_provider"),
            op.f("ix_users_principal_id"),
            op.f("ix_users_email"),
        ):
            if _index_exists(users_table, index_name):
                op.drop_index(index_name, table_name=users_table)
        op.drop_table(users_table)
