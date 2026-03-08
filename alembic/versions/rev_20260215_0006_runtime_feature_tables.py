"""Add runtime feature tables used by mounted production routes.

Revision ID: 20260215_0006
Revises: 20260215_0005
Create Date: 2026-02-15 14:35:00
"""

from __future__ import annotations

import importlib
from typing import Any, Sequence

import sqlalchemy as sa
from sqlmodel import SQLModel

from server.models import (
    AIChangeProposal,
    AIValidationFailure,
    Approval,
    EncryptionKeyRecord,
    PIIAIConversationToken,
    PIIAuditEntry,
    PIIHumanMapping,
    PIISession,
    RefreshToken,
    SecurityPolicy,
    Trace,
    UserPIIPermissions,
    UserSession,
)
from server.policy_governance.kernel.master_key import MasterKeyRecord


op: Any = importlib.import_module("alembic.op")

REVISION: str = "20260215_0006"
DOWN_REVISION: str | None = "20260215_0005"
BRANCH_LABELS: Sequence[str] | None = None
DEPENDS_ON: Sequence[str] | None = None

globals()["revision"] = REVISION
globals()["down_revision"] = DOWN_REVISION
globals()["branch_labels"] = BRANCH_LABELS
globals()["depends_on"] = DEPENDS_ON

_MODEL_REGISTRATION_SENTINEL = (
    Approval,
    Trace,
    SecurityPolicy,
    RefreshToken,
    UserSession,
    PIIAuditEntry,
    PIISession,
    PIIHumanMapping,
    PIIAIConversationToken,
    UserPIIPermissions,
    EncryptionKeyRecord,
    AIValidationFailure,
    AIChangeProposal,
    MasterKeyRecord,
)

_TARGET_TABLE_ORDER = (
    "approvals",
    "traces",
    "security_policies",
    "refresh_tokens",
    "user_sessions",
    "pii_audit_log",
    "pii_sessions",
    "pii_human_mappings",
    "pii_ai_tokens",
    "user_pii_permissions",
    "encryption_keys",
    "ai_validation_failures",
    "ai_change_proposals",
    "master_key_config",
)


def _table_exists(table_name: str) -> bool:
    """Return True when table exists in the active database schema."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return table_name in inspector.get_table_names()


def _resolve_table(table_name: str) -> sa.Table:
    """Resolve a SQLModel metadata table by name."""
    table = SQLModel.metadata.tables.get(table_name)
    if table is None:
        raise RuntimeError(f"SQLModel metadata does not include expected table '{table_name}'.")
    return table


def _create_table_and_indexes(table_name: str) -> None:
    """Create table and metadata indexes when absent."""
    if _table_exists(table_name):
        return

    bind = op.get_bind()
    table = _resolve_table(table_name)
    table.create(bind, checkfirst=True)
    for index in table.indexes:
        index.create(bind=bind, checkfirst=True)


def _drop_table_if_exists(table_name: str) -> None:
    """Drop a table when it exists."""
    if not _table_exists(table_name):
        return
    op.drop_table(table_name)


def upgrade() -> None:
    """Apply runtime feature compatibility tables."""
    for table_name in _TARGET_TABLE_ORDER:
        _create_table_and_indexes(table_name)


def downgrade() -> None:
    """Rollback runtime feature compatibility tables."""
    for table_name in reversed(_TARGET_TABLE_ORDER):
        _drop_table_if_exists(table_name)
