#!/usr/bin/env python3
"""Bootstrap runtime schema and guardrails state for CI test jobs."""

from __future__ import annotations

import asyncio
from importlib import import_module
import os
from pathlib import Path

from server.mcp.guardrails_sync import sync_guardrails_release
from server.models import database


def _register_sqlmodel_tables() -> None:
    """Import table modules so SQLModel metadata includes runtime governance tables."""
    import_module("server.models.formal_security_schemas")
    import_module("server.mcp.job_store")


async def _initialize_database() -> None:
    """Create missing SQLModel tables in the active runtime database."""
    _register_sqlmodel_tables()
    await database.init_db()


def main() -> int:
    """Initialize schema and publish a deterministic active guardrails release."""
    asyncio.run(_initialize_database())

    guardrails_path = Path(__file__).resolve().parents[1] / "mcp_guardrails.yaml"
    git_sha = os.getenv("GITHUB_SHA", "ci-local-bootstrap")
    normalized_sha = git_sha[:64] if git_sha else "ci-local-bootstrap"
    sync_guardrails_release(path=guardrails_path, git_sha=normalized_sha)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
