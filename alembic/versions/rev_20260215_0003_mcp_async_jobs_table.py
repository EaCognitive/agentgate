"""Add MCP async jobs table for migration-managed runtime schema.

Revision ID: 20260215_0003
Revises: 20260212_0002
Create Date: 2026-02-15 11:30:00
"""

from __future__ import annotations

import importlib
from typing import Any, Sequence

import sqlalchemy as sa


op: Any = importlib.import_module("alembic.op")

REVISION: str = "20260215_0003"
DOWN_REVISION: str | None = "20260212_0002"
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


def _create_index_if_missing(index_name: str, table_name: str, columns: list[str]) -> None:
    """Create an index only when it is absent."""
    if _index_exists(table_name, index_name):
        return
    op.create_index(index_name, table_name, columns, unique=False)


def upgrade() -> None:
    """Apply MCP async job schema."""
    table_name = "mcp_async_jobs"
    if not _table_exists(table_name):
        op.create_table(
            table_name,
            sa.Column("job_id", sa.String(length=64), nullable=False),
            sa.Column("operation", sa.String(length=128), nullable=False),
            sa.Column("request_id", sa.String(length=64), nullable=False),
            sa.Column("status", sa.String(length=32), nullable=False),
            sa.Column("progress_pct", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("message", sa.String(length=2048), nullable=False, server_default=""),
            sa.Column("result_json", sa.JSON(), nullable=True),
            sa.Column("error_json", sa.JSON(), nullable=True),
            sa.Column("requires_input_payload_json", sa.JSON(), nullable=True),
            sa.Column(
                "started_at",
                sa.DateTime(),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.PrimaryKeyConstraint("job_id"),
        )

    _create_index_if_missing(op.f("ix_mcp_async_jobs_operation"), table_name, ["operation"])
    _create_index_if_missing(op.f("ix_mcp_async_jobs_request_id"), table_name, ["request_id"])
    _create_index_if_missing(op.f("ix_mcp_async_jobs_status"), table_name, ["status"])


def downgrade() -> None:
    """Rollback MCP async job schema."""
    table_name = "mcp_async_jobs"
    if not _table_exists(table_name):
        return

    for index_name in (
        op.f("ix_mcp_async_jobs_status"),
        op.f("ix_mcp_async_jobs_request_id"),
        op.f("ix_mcp_async_jobs_operation"),
    ):
        if _index_exists(table_name, index_name):
            op.drop_index(index_name, table_name=table_name)

    op.drop_table(table_name)
