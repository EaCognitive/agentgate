#!/usr/bin/env python3
"""Backup verification utilities for AgentGate.

Provides structural and data integrity checks for backup files or live databases.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from dataclasses import dataclass
from typing import Any

from sqlalchemy import MetaData, Table, create_engine, inspect, select, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import SQLAlchemyError

logger = logging.getLogger(__name__)
BACKUP_VERIFY_ERRORS = (OSError, RuntimeError, SQLAlchemyError, ValueError)


@dataclass(frozen=True)
class TableSpec:
    """Required table schema expectations."""

    name: str
    required_columns: set[str]


REQUIRED_TABLES: list[TableSpec] = [
    TableSpec("trace", {"id", "created_at", "data"}),
    TableSpec("apikey", {"id", "key", "created_at"}),
    TableSpec("user", {"id", "email", "created_at"}),
    TableSpec("approvalrequest", {"id", "status", "created_at"}),
    TableSpec("datasetexample", {"id", "input", "output"}),
]

REQUIRED_INDEXES: dict[str, set[str]] = {
    "trace": {"idx_trace_created"},
    "user": {"idx_user_email"},
}


class BackupVerifier:
    """Verify database backups for completeness and integrity."""

    def __init__(self, database_url: str) -> None:
        self.database_url = database_url
        self._engine: Engine | None = None
        self._connection: Connection | None = None
        self._dialect: str | None = None

    def connect(self) -> bool:
        """Connect to the database. Returns True on success."""
        if self._connection is not None:
            return True
        try:
            self._engine = create_engine(self.database_url, future=True)
            self._connection = self._engine.connect()
            self._dialect = self._engine.dialect.name
            return True
        except BACKUP_VERIFY_ERRORS as exc:  # pragma: no cover - defensive for env failures
            logger.warning("Database connection failed: %s", exc)
            self._connection = None
            if self._engine is not None:
                self._engine.dispose()
            self._engine = None
            self._dialect = None
            return False

    def close(self) -> None:
        """Close database connection."""
        try:
            if self._connection is not None:
                self._connection.close()
            if self._engine is not None:
                self._engine.dispose()
        finally:
            self._connection = None
            self._engine = None
            self._dialect = None

    def verify_connectivity(self) -> bool:
        """Verify basic connectivity."""
        return self.connect()

    def _get_inspector(self):
        if self._engine is None:
            raise RuntimeError("Database engine not initialized")
        return inspect(self._engine)

    def _get_table(self, table_name: str) -> Table:
        """Reflect an expected table for safe aggregate queries."""
        if self._connection is None:
            raise RuntimeError("Database connection not initialized")
        allowed_tables = {spec.name for spec in REQUIRED_TABLES}
        if table_name not in allowed_tables:
            raise ValueError(f"Unexpected table name: {table_name}")
        metadata = MetaData()
        return Table(table_name, metadata, autoload_with=self._connection)

    def verify_tables(self) -> tuple[bool, list[str]]:
        """Verify required tables exist."""
        if not self.connect():
            return False, []

        inspector = self._get_inspector()
        tables = inspector.get_table_names()
        existing = set(tables)
        required = {spec.name for spec in REQUIRED_TABLES}

        missing = required - existing
        if missing:
            logger.warning("Missing required tables: %s", ", ".join(sorted(missing)))
            return False, tables

        return True, tables

    def verify_table_structure(self, table_name: str) -> bool:
        """Verify expected columns exist in a table."""
        if not self.connect():
            return False

        inspector = self._get_inspector()
        if table_name not in inspector.get_table_names():
            logger.warning("Table not found: %s", table_name)
            return False

        columns = {col["name"] for col in inspector.get_columns(table_name)}
        spec = next((t for t in REQUIRED_TABLES if t.name == table_name), None)
        if spec is None:
            logger.info("No schema spec defined for table: %s", table_name)
            return True

        missing = spec.required_columns - columns
        if missing:
            logger.warning(
                "Table %s missing required columns: %s",
                table_name,
                ", ".join(sorted(missing)),
            )
            return False

        return True

    def verify_data_integrity(self) -> dict[str, dict[str, Any]]:
        """Verify row counts and NULL IDs across key tables."""
        if not self.connect():
            return {}

        assert self._connection is not None

        results: dict[str, dict[str, Any]] = {}
        for spec in REQUIRED_TABLES:
            table = spec.name
            table_result: dict[str, Any] = {"row_count": 0, "null_ids": 0, "integrity_ok": True}

            try:
                reflected_table = self._get_table(table)
                row_count = self._count_rows(reflected_table)
                null_ids = self._count_rows(reflected_table, null_ids_only=True)
                table_result["row_count"] = int(row_count or 0)
                table_result["null_ids"] = int(null_ids or 0)
                table_result["integrity_ok"] = table_result["null_ids"] == 0
            except (RuntimeError, SQLAlchemyError, ValueError) as exc:
                logger.warning("Integrity check failed for table %s: %s", table, exc)
                table_result["integrity_ok"] = False

            results[table] = table_result

        return results

    def _count_rows(self, reflected_table: Table, *, null_ids_only: bool = False) -> int:
        """Count rows in a reflected table, optionally only rows with NULL IDs."""
        if self._connection is None:
            raise RuntimeError("Database connection not initialized")
        statement = select(text("count(*)")).select_from(reflected_table)
        if null_ids_only:
            statement = statement.where(reflected_table.c.id.is_(None))
        result = self._connection.execute(statement).scalar()
        return int(result or 0)

    def verify_indexes(self) -> bool:
        """Verify required indexes exist."""
        if not self.connect():
            return False

        inspector = self._get_inspector()
        for table, expected_indexes in REQUIRED_INDEXES.items():
            if table not in inspector.get_table_names():
                logger.warning("Cannot verify indexes; table missing: %s", table)
                return False

            existing = {idx["name"] for idx in inspector.get_indexes(table)}
            missing = expected_indexes - existing
            if missing:
                logger.warning(
                    "Table %s missing required indexes: %s",
                    table,
                    ", ".join(sorted(missing)),
                )
                return False

        return True

    def verify_foreign_keys(self) -> bool:
        """Verify foreign key integrity (where supported)."""
        if not self.connect():
            return False

        assert self._connection is not None

        if self._dialect == "sqlite":
            rows = self._connection.execute(text("PRAGMA foreign_key_check")).fetchall()
            if rows:
                logger.warning("Foreign key violations detected: %s", rows)
                return False
            return True

        # For non-SQLite, we can only verify presence of constraints.
        inspector = self._get_inspector()
        for spec in REQUIRED_TABLES:
            try:
                _ = inspector.get_foreign_keys(spec.name)
            except (RuntimeError, SQLAlchemyError, ValueError) as exc:
                logger.warning("Foreign key inspection failed for %s: %s", spec.name, exc)
                return False

        logger.info("Foreign key integrity checks are limited for %s", self._dialect)
        return True

    def run_full_verification(self) -> bool:
        """Run full verification suite and return overall success."""
        if not self.verify_connectivity():
            return False

        try:
            ok, _ = self.verify_tables()
            if not ok:
                return False

            for spec in REQUIRED_TABLES:
                if not self.verify_table_structure(spec.name):
                    return False

            integrity = self.verify_data_integrity()
            for table, result in integrity.items():
                if not result.get("integrity_ok", False):
                    logger.warning("Integrity failed for table %s", table)
                    return False

            if not self.verify_indexes():
                logger.warning("Index verification failed; continuing with integrity checks")

            if not self.verify_foreign_keys():
                return False

            return True
        finally:
            self.close()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify AgentGate backups.")
    parser.add_argument(
        "--database-url",
        dest="database_url",
        default=os.getenv("DATABASE_URL"),
        help="Database URL to verify (defaults to DATABASE_URL env var)",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Emit JSON result",
    )
    return parser


def main() -> int:
    """CLI entry point for verifying backup integrity and restoring from cloud storage."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = _build_parser()
    args = parser.parse_args()

    if not args.database_url:
        logger.error("DATABASE_URL not provided")
        return 2

    verifier = BackupVerifier(args.database_url)
    success = verifier.run_full_verification()

    if args.json_output:
        print(json.dumps({"success": success}, indent=2))
    else:
        print("Backup verification:", "OK" if success else "FAILED")

    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
