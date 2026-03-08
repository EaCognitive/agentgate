# Alembic Database Migrations

This directory contains Alembic database migration scripts for AgentGate.

## Quick Start

```bash
# Create a new migration
make migrate-create MESSAGE="Add new feature"

# Apply all pending migrations
make migrate-up

# Rollback last migration
make migrate-down

# View migration history
make migrate-history
```

## Manual Commands

```bash
# Create a new migration
alembic revision --autogenerate -m "Your message here"

# Apply migrations
alembic upgrade head

# Rollback one migration
alembic downgrade -1

# View current version
alembic current

# View migration history
alembic history --verbose
```

## Development vs Production

The migration system automatically detects your database from the `DATABASE_URL` environment variable:

- **Development**: Uses SQLite by default (`sqlite:///./agentgate.db`)
- **Production**: Uses PostgreSQL (set `DATABASE_URL` to PostgreSQL connection string)

## Best Practices

1. **Always review auto-generated migrations** before applying them
2. **Test migrations on a copy of production data** before deploying
3. **Never edit applied migrations** - create a new migration instead
4. **Keep migrations small and focused** - one logical change per migration
5. **Add data migrations separately** from schema migrations

## Troubleshooting

### "Target database is not up to date"
Run `alembic upgrade head` to apply pending migrations.

### "Can't locate revision"
Delete `alembic/versions/*.py` files and recreate with `alembic revision --autogenerate -m "Initial schema"`.

### Multiple heads detected
Run `alembic merge` to merge divergent migration branches.
