"""Add remaining SQLModel metadata tables for runtime schema parity.

Revision ID: 20260215_0007
Revises: 20260215_0006
Create Date: 2026-02-15 15:40:00
"""

from __future__ import annotations

import importlib
from typing import Any, Sequence

import sqlalchemy as sa
from sqlmodel import SQLModel

from server.models.audit_schemas import CostRecord
from server.models.dataset_schemas import Dataset, TestCase, TestResult, TestRun
from server.models.formal_security_schemas import (
    CoSignatureRecord,
    DeceptionTriggerRecord,
    GlobalRevocationRecord,
    HoneyTokenRecord,
    SafetyNodeRecord,
    SynthesizedInvariantRecord,
    TransparencyLogRecord,
)
from server.models.prompt_schemas import PromptTemplate


op: Any = importlib.import_module("alembic.op")

REVISION: str = "20260215_0007"
DOWN_REVISION: str | None = "20260215_0006"
BRANCH_LABELS: Sequence[str] | None = None
DEPENDS_ON: Sequence[str] | None = None

globals()["revision"] = REVISION
globals()["down_revision"] = DOWN_REVISION
globals()["branch_labels"] = BRANCH_LABELS
globals()["depends_on"] = DEPENDS_ON

_MODEL_REGISTRATION_SENTINEL = (
    Dataset,
    TestCase,
    TestRun,
    TestResult,
    CostRecord,
    PromptTemplate,
    SynthesizedInvariantRecord,
    HoneyTokenRecord,
    DeceptionTriggerRecord,
    SafetyNodeRecord,
    TransparencyLogRecord,
    CoSignatureRecord,
    GlobalRevocationRecord,
)

_TARGET_TABLE_ORDER = (
    "datasets",
    "test_cases",
    "test_runs",
    "test_results",
    "cost_records",
    "prompt_templates",
    "synthesized_invariants",
    "honey_tokens",
    "deception_triggers",
    "safety_nodes",
    "transparency_log",
    "co_signatures",
    "global_revocations",
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
    """Apply remaining runtime schema parity tables."""
    for table_name in _TARGET_TABLE_ORDER:
        _create_table_and_indexes(table_name)


def downgrade() -> None:
    """Rollback remaining runtime schema parity tables."""
    for table_name in reversed(_TARGET_TABLE_ORDER):
        _drop_table_if_exists(table_name)
