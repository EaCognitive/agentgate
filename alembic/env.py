"""
Alembic migration environment configuration for AgentGate.

This module configures Alembic to work with SQLModel models and supports
both SQLite (development) and PostgreSQL (production) databases.

Features:
- Auto-detects DATABASE_URL from environment
- Supports both sync and async migrations
- Works with existing SQLModel metadata
- Handles schema comparisons intelligently

@author Erick | Founding Principal AI Architect
"""

import importlib
import os
import sys
from typing import Any
from logging.config import fileConfig

from sqlmodel import SQLModel

# Add parent directory to path to import server modules
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Import model modules to register all table definitions with SQLModel metadata.
_MODEL_MODULES = (
    "server.models.user_schemas",
    "server.models.audit_schemas",
    "server.models.trace_schemas",
    "server.models.approval_schemas",
    "server.models.dataset_schemas",
    "server.models.pii_schemas",
    "server.models.security_policy_schemas",
    "server.models.prompt_schemas",
    "server.models.formal_security_schemas",
    "server.models.identity_schemas",
)
_MODEL_REGISTRATION_SENTINEL = tuple(importlib.import_module(name) for name in _MODEL_MODULES)
get_sync_engine = importlib.import_module("server.models.database").get_sync_engine

context: Any = importlib.import_module("alembic.context")

# This is the Alembic Config object
config = context.config

# Interpret the config file for Python logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Set target metadata for 'autogenerate' support
target_metadata = SQLModel.metadata

_AUTOGENERATE_IGNORE_TABLES = frozenset(
    {
        "api_keys",
        "mcp_async_jobs",
        "mcp_guardrails_definitions",
        "mcp_guardrails_releases",
        "master_key_config",
    }
)


def include_object(object_, name, type_, reflected, compare_to):
    """Skip migration-managed tables during autogenerate diffing."""
    if type_ == "table" and name in _AUTOGENERATE_IGNORE_TABLES:
        return False

    table = getattr(object_, "table", None)
    table_name = getattr(table, "name", None)
    if table_name in _AUTOGENERATE_IGNORE_TABLES:
        return False

    compare_table = getattr(compare_to, "table", None)
    compare_table_name = getattr(compare_table, "name", None)
    if compare_table_name in _AUTOGENERATE_IGNORE_TABLES:
        return False

    _ = reflected
    return True


# Load DATABASE_URL from environment
database_url = os.getenv("DATABASE_URL", "sqlite:///./agentgate.db")

# Convert async URLs to sync for Alembic
# Alembic uses synchronous SQLAlchemy, so we need to convert async drivers
if "+aiosqlite" in database_url:
    database_url = database_url.replace("+aiosqlite", "")
elif "+asyncpg" in database_url:
    database_url = database_url.replace("+asyncpg", "+psycopg2")

# Set the URL in Alembic config
config.set_main_option("sqlalchemy.url", database_url)


def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode.

    This configures the context with just a URL and not an Engine,
    though an Engine is acceptable here as well. By skipping the Engine
    creation we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the script output.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        include_object=include_object,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """
    Run migrations in 'online' mode.

    In this scenario we need to create an Engine and associate a connection
    with the context.
    """
    connectable = get_sync_engine()

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_object=include_object,
            compare_type=True,
            compare_server_default=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
