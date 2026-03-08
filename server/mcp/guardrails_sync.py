"""GitOps guardrails sync command for MCP policy governance.

Usage:
    python -m server.mcp.guardrails_sync --path <yaml_dir> --git-sha <sha>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import text

from server.models.database import get_sync_engine

from .guardrails import (
    GUARDRAILS_DEFINITIONS_TABLE,
    GUARDRAILS_RELEASES_TABLE,
    is_strict_runtime_profile,
    resolve_runtime_profile,
)

logger = logging.getLogger(__name__)

_YAML_SUFFIXES = {".yaml", ".yml"}
_PLACEHOLDER_GIT_SHAS = {"unknown"}
_EXPECTED_RELEASES_TABLE = "mcp_guardrails_releases"
_EXPECTED_DEFINITIONS_TABLE = "mcp_guardrails_definitions"


def _assert_expected_table_names() -> None:
    """Fail fast if shared table constants drift from approved table names."""
    if GUARDRAILS_RELEASES_TABLE != _EXPECTED_RELEASES_TABLE:
        raise RuntimeError(
            "Unexpected guardrails release table name. "
            f"Expected {_EXPECTED_RELEASES_TABLE}, got {GUARDRAILS_RELEASES_TABLE}."
        )
    if GUARDRAILS_DEFINITIONS_TABLE != _EXPECTED_DEFINITIONS_TABLE:
        raise RuntimeError(
            "Unexpected guardrails definitions table name. "
            f"Expected {_EXPECTED_DEFINITIONS_TABLE}, got {GUARDRAILS_DEFINITIONS_TABLE}."
        )


@dataclass(slots=True)
class GuardrailDocument:
    """Canonicalized guardrails document entry."""

    source_file: str
    document_index: int
    definition_hash: str
    definition_json: str


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _discover_yaml_files(path: Path) -> list[Path]:
    if path.is_file():
        if path.suffix.lower() not in _YAML_SUFFIXES:
            raise ValueError(f"Expected YAML file, got '{path}'.")
        return [path]

    if not path.exists() or not path.is_dir():
        raise FileNotFoundError(f"Guardrails path not found: '{path}'.")

    files = sorted(
        item for item in path.rglob("*") if item.is_file() and item.suffix.lower() in _YAML_SUFFIXES
    )
    if not files:
        raise FileNotFoundError(f"No YAML files found under '{path}'.")
    return files


def _load_documents(base_path: Path, files: list[Path]) -> list[GuardrailDocument]:
    documents: list[GuardrailDocument] = []
    root = base_path if base_path.is_dir() else base_path.parent
    root = root.resolve()

    for file_path in files:
        file_text = file_path.read_text(encoding="utf-8")
        parsed_docs = list(yaml.safe_load_all(file_text))
        for index, parsed in enumerate(parsed_docs):
            if parsed is None:
                continue
            canonical = _canonical_json(parsed)
            documents.append(
                GuardrailDocument(
                    source_file=file_path.resolve().relative_to(root).as_posix(),
                    document_index=index,
                    definition_hash=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
                    definition_json=canonical,
                )
            )

    if not documents:
        raise ValueError(f"No non-empty guardrails YAML documents found in '{base_path}'.")
    return documents


def _release_hash(documents: list[GuardrailDocument]) -> str:
    joined = "\n".join(
        f"{doc.source_file}:{doc.document_index}:{doc.definition_hash}"
        for doc in sorted(
            documents,
            key=lambda item: (item.source_file, item.document_index),
        )
    )
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def _normalize_git_sha(git_sha: str) -> str:
    normalized = git_sha.strip()
    if not normalized:
        raise ValueError("Guardrails sync requires a non-empty git SHA.")
    if normalized.lower() in _PLACEHOLDER_GIT_SHAS:
        raise ValueError(
            "Guardrails sync requires a deterministic git SHA, "
            f"got placeholder value '{normalized}'."
        )
    return normalized


def _ensure_guardrails_tables(connection: Any) -> None:
    """Create guardrails sync tables if missing (sync command only)."""
    connection.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS mcp_guardrails_releases (
                git_sha VARCHAR(128) PRIMARY KEY,
                release_hash VARCHAR(64) NOT NULL,
                source_path TEXT NOT NULL,
                file_count INTEGER NOT NULL,
                document_count INTEGER NOT NULL,
                is_active BOOLEAN NOT NULL,
                applied_at TIMESTAMP NOT NULL,
                activated_at TIMESTAMP NOT NULL
            )
            """
        )
    )
    connection.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS mcp_guardrails_definitions (
                git_sha VARCHAR(128) NOT NULL,
                source_file TEXT NOT NULL,
                document_index INTEGER NOT NULL,
                definition_hash VARCHAR(64) NOT NULL,
                definition_json TEXT NOT NULL,
                PRIMARY KEY (git_sha, source_file, document_index),
                FOREIGN KEY (git_sha)
                    REFERENCES mcp_guardrails_releases(git_sha)
                    ON DELETE CASCADE
            )
            """
        )
    )


def sync_guardrails_release(path: Path, git_sha: str) -> dict[str, Any]:
    """Idempotently upsert GitOps guardrails definitions into runtime DB tables."""
    _assert_expected_table_names()
    normalized_git_sha = _normalize_git_sha(git_sha)
    resolved_path = path.expanduser().resolve()
    files = _discover_yaml_files(resolved_path)
    documents = _load_documents(resolved_path, files)
    release_hash = _release_hash(documents)
    applied_at = datetime.now(timezone.utc).replace(tzinfo=None)

    engine = get_sync_engine()
    with engine.begin() as connection:
        _ensure_guardrails_tables(connection)

        connection.execute(
            text(
                """
                INSERT INTO mcp_guardrails_releases
                (
                    git_sha,
                    release_hash,
                    source_path,
                    file_count,
                    document_count,
                    is_active,
                    applied_at,
                    activated_at
                )
                VALUES
                (
                    :git_sha,
                    :release_hash,
                    :source_path,
                    :file_count,
                    :document_count,
                    :is_active,
                    :applied_at,
                    :activated_at
                )
                ON CONFLICT (git_sha) DO UPDATE SET
                    release_hash = excluded.release_hash,
                    source_path = excluded.source_path,
                    file_count = excluded.file_count,
                    document_count = excluded.document_count,
                    is_active = excluded.is_active,
                    applied_at = excluded.applied_at,
                    activated_at = excluded.activated_at
                """
            ),
            {
                "git_sha": normalized_git_sha,
                "release_hash": release_hash,
                "source_path": str(resolved_path),
                "file_count": len(files),
                "document_count": len(documents),
                "is_active": True,
                "applied_at": applied_at,
                "activated_at": applied_at,
            },
        )

        connection.execute(
            text(
                """
                UPDATE mcp_guardrails_releases
                SET is_active = :inactive
                WHERE git_sha <> :git_sha
                  AND is_active = :active_true
                """
            ),
            {"git_sha": normalized_git_sha, "active_true": True, "inactive": False},
        )
        connection.execute(
            text(
                """
                UPDATE mcp_guardrails_releases
                SET is_active = :active_true,
                    activated_at = :activated_at
                WHERE git_sha = :git_sha
                """
            ),
            {
                "git_sha": normalized_git_sha,
                "active_true": True,
                "activated_at": applied_at,
            },
        )

        connection.execute(
            text("DELETE FROM mcp_guardrails_definitions WHERE git_sha = :git_sha"),
            {"git_sha": normalized_git_sha},
        )

        insert_definition_statement = text(
            """
            INSERT INTO mcp_guardrails_definitions
            (
                git_sha,
                source_file,
                document_index,
                definition_hash,
                definition_json
            )
            VALUES
            (
                :git_sha,
                :source_file,
                :document_index,
                :definition_hash,
                :definition_json
            )
            ON CONFLICT (git_sha, source_file, document_index) DO UPDATE SET
                definition_hash = excluded.definition_hash,
                definition_json = excluded.definition_json
            """
        )

        for document in documents:
            connection.execute(
                insert_definition_statement,
                {
                    "git_sha": normalized_git_sha,
                    "source_file": document.source_file,
                    "document_index": document.document_index,
                    "definition_hash": document.definition_hash,
                    "definition_json": document.definition_json,
                },
            )

    runtime_profile = resolve_runtime_profile()
    summary = {
        "success": True,
        "git_sha": normalized_git_sha,
        "release_hash": release_hash,
        "source_path": str(resolved_path),
        "files_synced": len(files),
        "documents_synced": len(documents),
        "active_release_promoted": True,
        "runtime_profile": runtime_profile,
        "strict_profile": is_strict_runtime_profile(runtime_profile),
    }
    logger.info(
        "Guardrails sync completed git_sha=%s release_hash=%s files=%s docs=%s",
        normalized_git_sha,
        release_hash,
        len(files),
        len(documents),
    )
    return summary


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sync GitOps guardrails into database tables.")
    parser.add_argument(
        "--path",
        required=True,
        help="Path to guardrails YAML directory or file.",
    )
    parser.add_argument(
        "--git-sha",
        required=True,
        help="Git commit SHA for this guardrails release.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for GitOps guardrails sync."""
    args = _parse_args(argv)
    logging.basicConfig(level=logging.INFO)

    summary = sync_guardrails_release(
        path=Path(str(args.path)),
        git_sha=str(args.git_sha),
    )
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
