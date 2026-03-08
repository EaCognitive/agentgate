"""Schema compatibility checks for readiness probes.

This module intentionally performs read-only schema inspection and never runs
DDL. Runtime pods must not mutate schema during startup.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import import_module
from pathlib import Path
from typing import Any

from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

_REQUIRED_RUNTIME_TABLES = frozenset(
    {
        "api_keys",
        "audit_log",
        "users",
        "system_settings",
        "security_threats",
        "delegation_grants",
        "decision_certificates",
        "execution_evidence_chain",
    }
)


@dataclass(slots=True)
class SchemaGuardResult:
    """Result for runtime schema compatibility checks."""

    compatible: bool
    reason: str
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of this result."""
        return {
            "ok": self.compatible,
            "reason": self.reason,
            "details": self.details,
        }


@lru_cache(maxsize=1)
def _expected_alembic_heads() -> set[str]:
    """Resolve expected Alembic head revisions from repository metadata."""
    try:
        alembic_config = import_module("alembic.config")
        alembic_script = import_module("alembic.script")
    except ModuleNotFoundError:
        logger.warning(
            "Alembic is not installed in this runtime; strict revision checks will be skipped."
        )
        return set()

    repo_root = Path(__file__).resolve().parents[2]
    alembic_ini = repo_root / "alembic.ini"
    script_location = repo_root / "alembic"
    if not alembic_ini.exists() or not script_location.exists():
        logger.warning(
            "Alembic metadata files were not found at %s and %s",
            alembic_ini,
            script_location,
        )
        return set()

    try:
        config = alembic_config.Config(str(alembic_ini))
        config.set_main_option("script_location", str(script_location))
        script = alembic_script.ScriptDirectory.from_config(config)
        return {str(revision) for revision in script.get_heads()}
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as exc:
        logger.warning(
            "Unable to resolve Alembic heads for schema guard checks: %s",
            exc,
        )
        return set()


def _read_schema_state(sync_connection: Any) -> tuple[set[str], set[str]]:
    """Collect table names and alembic heads from a sync SQLAlchemy connection."""
    inspector = inspect(sync_connection)
    table_names = set(inspector.get_table_names())
    database_heads: set[str] = set()

    if "alembic_version" in table_names:
        rows = sync_connection.execute(text("SELECT version_num FROM alembic_version")).fetchall()
        database_heads = {str(row[0]) for row in rows if row and row[0]}

    return table_names, database_heads


async def check_schema_compatibility(
    session: AsyncSession,
    *,
    strict_profile: bool,
) -> SchemaGuardResult:
    """Validate runtime schema compatibility in read-only mode."""
    try:
        connection = await session.connection()
        table_names, database_heads = await connection.run_sync(_read_schema_state)
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as exc:
        return SchemaGuardResult(
            compatible=False,
            reason="schema_inspection_failed",
            details={"error": str(exc)},
        )

    missing_tables = sorted(_REQUIRED_RUNTIME_TABLES.difference(table_names))
    if missing_tables:
        return SchemaGuardResult(
            compatible=False,
            reason="required_tables_missing",
            details={"missing_tables": missing_tables},
        )

    if not strict_profile:
        return SchemaGuardResult(
            compatible=True,
            reason="schema_compatible",
            details={
                "checked_tables": sorted(_REQUIRED_RUNTIME_TABLES),
                "strict_profile": False,
            },
        )

    expected_heads = _expected_alembic_heads()
    if expected_heads:
        if "alembic_version" not in table_names:
            return SchemaGuardResult(
                compatible=False,
                reason="alembic_version_table_missing",
                details={"expected_heads": sorted(expected_heads)},
            )

        if database_heads != expected_heads:
            return SchemaGuardResult(
                compatible=False,
                reason="schema_revision_mismatch",
                details={
                    "expected_heads": sorted(expected_heads),
                    "database_heads": sorted(database_heads),
                },
            )

    return SchemaGuardResult(
        compatible=True,
        reason="schema_compatible",
        details={
            "checked_tables": sorted(_REQUIRED_RUNTIME_TABLES),
            "strict_profile": True,
            "expected_heads": sorted(expected_heads),
            "database_heads": sorted(database_heads),
        },
    )
