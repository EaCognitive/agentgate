"""Add runtime security tables required for setup and threat logging.

Revision ID: 20260215_0005
Revises: 20260215_0004
Create Date: 2026-02-15 14:20:00
"""

from __future__ import annotations

import importlib
from typing import Any, Sequence

import sqlalchemy as sa


op: Any = importlib.import_module("alembic.op")

REVISION: str = "20260215_0005"
DOWN_REVISION: str | None = "20260215_0004"
BRANCH_LABELS: Sequence[str] | None = None
DEPENDS_ON: Sequence[str] | None = None

globals()["revision"] = REVISION
globals()["down_revision"] = DOWN_REVISION
globals()["branch_labels"] = BRANCH_LABELS
globals()["depends_on"] = DEPENDS_ON

THREAT_STATUS_ENUM_NAME = "threatstatus"
THREAT_STATUS_VALUES = ("PENDING", "ACKNOWLEDGED", "RESOLVED", "DISMISSED")


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


def _threat_status_enum() -> sa.Enum:
    """Return SQLAlchemy enum instance for threat status."""
    return sa.Enum(*THREAT_STATUS_VALUES, name=THREAT_STATUS_ENUM_NAME)


def _drop_threat_status_enum_if_unused() -> None:
    """Drop threatstatus enum when no columns reference it."""
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    enum_is_used = bind.execute(
        sa.text(
            """
            SELECT EXISTS (
                SELECT 1
                FROM pg_attribute attr
                JOIN pg_class cls ON cls.oid = attr.attrelid
                JOIN pg_namespace namespace ON namespace.oid = cls.relnamespace
                JOIN pg_type typ ON typ.oid = attr.atttypid
                WHERE namespace.nspname = current_schema()
                  AND cls.relkind = 'r'
                  AND attr.attnum > 0
                  AND NOT attr.attisdropped
                  AND typ.typname = :enum_name
            )
            """
        ),
        {"enum_name": THREAT_STATUS_ENUM_NAME},
    ).scalar_one()
    if enum_is_used:
        return
    _threat_status_enum().drop(bind, checkfirst=True)


def _create_audit_log_table() -> None:
    """Create audit_log table and indexes when missing."""
    table_name = "audit_log"
    if not _table_exists(table_name):
        op.create_table(
            table_name,
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column(
                "timestamp",
                sa.DateTime(),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.Column("event_type", sa.String(length=255), nullable=False),
            sa.Column("actor", sa.String(length=255), nullable=True),
            sa.Column("tool", sa.String(length=255), nullable=True),
            sa.Column("inputs", sa.JSON(), nullable=True),
            sa.Column("result", sa.String(length=255), nullable=True),
            sa.Column("details", sa.JSON(), nullable=True),
            sa.Column("ip_address", sa.String(length=64), nullable=True),
        )

    _create_index_if_missing(op.f("ix_audit_log_timestamp"), table_name, ["timestamp"])
    _create_index_if_missing(op.f("ix_audit_log_event_type"), table_name, ["event_type"])


def _create_api_keys_table() -> None:
    """Create api_keys table and indexes when missing."""
    table_name = "api_keys"
    if not _table_exists(table_name):
        op.create_table(
            table_name,
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column("name", sa.String(length=128), nullable=False),
            sa.Column("key_hash", sa.String(length=128), nullable=False),
            sa.Column("key_prefix", sa.String(length=12), nullable=False),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("scopes", sa.String(length=1024), nullable=False, server_default="*"),
            sa.Column(
                "created_at",
                sa.DateTime(),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.Column("last_used_at", sa.DateTime(), nullable=True),
            sa.Column("expires_at", sa.DateTime(), nullable=True),
            sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("revoked_at", sa.DateTime(), nullable=True),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        )

    _create_index_if_missing(op.f("ix_api_keys_name"), table_name, ["name"])
    _create_index_if_missing(op.f("ix_api_keys_user_id"), table_name, ["user_id"])


def _create_security_threats_table() -> None:
    """Create security_threats table and indexes when missing."""
    table_name = "security_threats"
    if not _table_exists(table_name):
        op.create_table(
            table_name,
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column("event_id", sa.String(length=64), nullable=False),
            sa.Column("event_type", sa.String(length=64), nullable=False),
            sa.Column("severity", sa.String(length=16), nullable=False),
            sa.Column(
                "status",
                _threat_status_enum(),
                nullable=False,
                server_default=THREAT_STATUS_VALUES[0],
            ),
            sa.Column("source_ip", sa.String(length=64), nullable=True),
            sa.Column("target", sa.String(length=255), nullable=True),
            sa.Column("description", sa.String(length=512), nullable=True),
            sa.Column(
                "detected_at",
                sa.DateTime(),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.Column("acknowledged_at", sa.DateTime(), nullable=True),
            sa.Column("resolved_at", sa.DateTime(), nullable=True),
            sa.Column("dismissed_at", sa.DateTime(), nullable=True),
            sa.Column("user_id", sa.Integer(), nullable=True),
            sa.Column("user_email", sa.String(length=255), nullable=True),
            sa.Column("metadata_json", sa.JSON(), nullable=True),
            sa.UniqueConstraint("event_id", name=op.f("uq_security_threats_event_id")),
        )

    _create_index_if_missing(op.f("ix_security_threats_event_id"), table_name, ["event_id"])
    _create_index_if_missing(op.f("ix_security_threats_event_type"), table_name, ["event_type"])
    _create_index_if_missing(op.f("ix_security_threats_severity"), table_name, ["severity"])
    _create_index_if_missing(op.f("ix_security_threats_status"), table_name, ["status"])
    _create_index_if_missing(op.f("ix_security_threats_detected_at"), table_name, ["detected_at"])
    _create_index_if_missing(op.f("ix_security_threats_user_id"), table_name, ["user_id"])


def upgrade() -> None:
    """Apply runtime security compatibility tables."""
    _create_audit_log_table()
    _create_api_keys_table()
    _create_security_threats_table()


def _drop_table_indexes(table_name: str, index_names: tuple[str, ...]) -> None:
    """Drop selected indexes for table when present."""
    if not _table_exists(table_name):
        return
    for index_name in index_names:
        if _index_exists(table_name, index_name):
            op.drop_index(index_name, table_name=table_name)


def downgrade() -> None:
    """Rollback runtime security compatibility tables."""
    _drop_table_indexes(
        "security_threats",
        (
            op.f("ix_security_threats_user_id"),
            op.f("ix_security_threats_detected_at"),
            op.f("ix_security_threats_status"),
            op.f("ix_security_threats_severity"),
            op.f("ix_security_threats_event_type"),
            op.f("ix_security_threats_event_id"),
        ),
    )
    if _table_exists("security_threats"):
        op.drop_table("security_threats")
        _drop_threat_status_enum_if_unused()

    _drop_table_indexes(
        "api_keys",
        (
            op.f("ix_api_keys_user_id"),
            op.f("ix_api_keys_name"),
        ),
    )
    if _table_exists("api_keys"):
        op.drop_table("api_keys")

    _drop_table_indexes(
        "audit_log",
        (
            op.f("ix_audit_log_event_type"),
            op.f("ix_audit_log_timestamp"),
        ),
    )
    if _table_exists("audit_log"):
        op.drop_table("audit_log")
