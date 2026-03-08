"""sync_full_schema_parity

Revision ID: 1093fdec7208
Revises: 20260215_0007
Create Date: 2026-02-15 15:50:35.614581

"""

import importlib
from typing import Any, Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


op: Any = importlib.import_module("alembic.op")
# revision identifiers, used by Alembic.
REVISION: str = "1093fdec7208"
DOWN_REVISION: Union[str, None] = "20260215_0007"
BRANCH_LABELS: Union[str, Sequence[str], None] = None
DEPENDS_ON: Union[str, Sequence[str], None] = None

globals()["revision"] = REVISION
globals()["down_revision"] = DOWN_REVISION
globals()["branch_labels"] = BRANCH_LABELS
globals()["depends_on"] = DEPENDS_ON

_FK_DELEGATION_GRANTS_ISSUED_BY = op.f("fk_delegation_grants_issued_by_user_id_users")
_FK_DELEGATION_REVOCATIONS_REVOKED_BY = op.f("fk_delegation_revocations_revoked_by_user_id_users")
_FK_IDENTITY_LINKS_USER = op.f("fk_identity_links_user_id_users")
_FK_ROLE_BINDINGS_CREATED_BY = op.f("fk_role_bindings_created_by_user_id_users")
_FK_VERIFICATION_GRANTS_USER = op.f("fk_verification_grants_user_id_users")


def upgrade() -> None:
    """Apply migration changes.

    This migration was auto-generated against PostgreSQL. ALL operations
    (ALTER COLUMN, CREATE FOREIGN KEY, DROP CONSTRAINT) are PostgreSQL-only.
    SQLite already has the correct schema from the CREATE TABLE migrations
    (0001-0007), so we skip this migration entirely on non-PostgreSQL backends.
    """
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    op.alter_column(
        "audit_log",
        "timestamp",
        existing_type=postgresql.TIMESTAMP(),
        server_default=None,
        existing_nullable=False,
    )
    op.create_index(
        op.f("ix_delegation_grants_issued_at"), "delegation_grants", ["issued_at"], unique=False
    )
    op.create_foreign_key(
        _FK_DELEGATION_GRANTS_ISSUED_BY,
        "delegation_grants",
        "users",
        ["issued_by_user_id"],
        ["id"],
    )
    op.create_foreign_key(
        _FK_DELEGATION_REVOCATIONS_REVOKED_BY,
        "delegation_revocations",
        "users",
        ["revoked_by_user_id"],
        ["id"],
    )
    op.create_foreign_key(
        _FK_IDENTITY_LINKS_USER,
        "identity_links",
        "users",
        ["user_id"],
        ["id"],
    )
    op.create_foreign_key(
        _FK_ROLE_BINDINGS_CREATED_BY,
        "role_bindings",
        "users",
        ["created_by_user_id"],
        ["id"],
    )
    op.alter_column(
        "security_threats",
        "status",
        existing_type=postgresql.ENUM(
            "PENDING", "ACKNOWLEDGED", "RESOLVED", "DISMISSED", name="threatstatus"
        ),
        server_default=None,
        existing_nullable=False,
    )
    op.alter_column(
        "security_threats",
        "detected_at",
        existing_type=postgresql.TIMESTAMP(),
        server_default=None,
        existing_nullable=False,
    )
    op.drop_constraint(op.f("uq_security_threats_event_id"), "security_threats", type_="unique")
    op.drop_index(op.f("ix_security_threats_event_id"), table_name="security_threats")
    op.create_index(
        op.f("ix_security_threats_event_id"), "security_threats", ["event_id"], unique=True
    )
    op.alter_column(
        "system_settings",
        "updated_at",
        existing_type=postgresql.TIMESTAMP(),
        server_default=None,
        existing_nullable=False,
    )
    op.drop_constraint(op.f("uq_system_settings_key"), "system_settings", type_="unique")
    op.drop_index(op.f("ix_system_settings_key"), table_name="system_settings")
    op.create_index(op.f("ix_system_settings_key"), "system_settings", ["key"], unique=True)
    op.alter_column(
        "users",
        "role",
        existing_type=sa.VARCHAR(length=50),
        server_default=None,
        existing_nullable=False,
    )
    op.alter_column(
        "users",
        "is_active",
        existing_type=sa.BOOLEAN(),
        server_default=None,
        existing_nullable=False,
    )
    op.alter_column(
        "users",
        "created_at",
        existing_type=postgresql.TIMESTAMP(),
        server_default=None,
        existing_nullable=False,
    )
    op.alter_column(
        "users",
        "must_change_password",
        existing_type=sa.BOOLEAN(),
        server_default=None,
        existing_nullable=False,
    )
    op.alter_column(
        "users",
        "is_default_credentials",
        existing_type=sa.BOOLEAN(),
        server_default=None,
        existing_nullable=False,
    )
    op.alter_column(
        "users",
        "failed_login_attempts",
        existing_type=sa.INTEGER(),
        server_default=None,
        existing_nullable=False,
    )
    op.alter_column(
        "users",
        "totp_enabled",
        existing_type=sa.BOOLEAN(),
        server_default=None,
        existing_nullable=False,
    )
    op.alter_column(
        "users",
        "identity_provider",
        existing_type=sa.VARCHAR(length=64),
        server_default=None,
        existing_nullable=False,
    )
    op.alter_column(
        "users",
        "tenant_id",
        existing_type=sa.VARCHAR(length=128),
        server_default=None,
        existing_nullable=False,
    )
    op.drop_constraint(op.f("uq_users_email"), "users", type_="unique")
    op.drop_index(op.f("ix_users_email"), table_name="users")
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)
    op.create_index(
        op.f("ix_verification_grants_issued_at"), "verification_grants", ["issued_at"], unique=False
    )
    op.create_foreign_key(
        _FK_VERIFICATION_GRANTS_USER,
        "verification_grants",
        "users",
        ["user_id"],
        ["id"],
    )
    # ### end Alembic commands ###


def downgrade() -> None:
    """Revert migration changes."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(
        _FK_VERIFICATION_GRANTS_USER,
        "verification_grants",
        type_="foreignkey",
    )
    op.drop_index(op.f("ix_verification_grants_issued_at"), table_name="verification_grants")
    op.drop_index(op.f("ix_users_email"), table_name="users")
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=False)
    op.create_unique_constraint(
        op.f("uq_users_email"), "users", ["email"], postgresql_nulls_not_distinct=False
    )
    op.alter_column(
        "users",
        "tenant_id",
        existing_type=sa.VARCHAR(length=128),
        server_default=sa.text("'default'::character varying"),
        existing_nullable=False,
    )
    op.alter_column(
        "users",
        "identity_provider",
        existing_type=sa.VARCHAR(length=64),
        server_default=sa.text("'local'::character varying"),
        existing_nullable=False,
    )
    op.alter_column(
        "users",
        "totp_enabled",
        existing_type=sa.BOOLEAN(),
        server_default=sa.text("false"),
        existing_nullable=False,
    )
    op.alter_column(
        "users",
        "failed_login_attempts",
        existing_type=sa.INTEGER(),
        server_default=sa.text("0"),
        existing_nullable=False,
    )
    op.alter_column(
        "users",
        "is_default_credentials",
        existing_type=sa.BOOLEAN(),
        server_default=sa.text("false"),
        existing_nullable=False,
    )
    op.alter_column(
        "users",
        "must_change_password",
        existing_type=sa.BOOLEAN(),
        server_default=sa.text("false"),
        existing_nullable=False,
    )
    op.alter_column(
        "users",
        "created_at",
        existing_type=postgresql.TIMESTAMP(),
        server_default=sa.text("CURRENT_TIMESTAMP"),
        existing_nullable=False,
    )
    op.alter_column(
        "users",
        "is_active",
        existing_type=sa.BOOLEAN(),
        server_default=sa.text("true"),
        existing_nullable=False,
    )
    op.alter_column(
        "users",
        "role",
        existing_type=sa.VARCHAR(length=50),
        server_default=sa.text("'viewer'::character varying"),
        existing_nullable=False,
    )
    op.drop_index(op.f("ix_system_settings_key"), table_name="system_settings")
    op.create_index(op.f("ix_system_settings_key"), "system_settings", ["key"], unique=False)
    op.create_unique_constraint(
        op.f("uq_system_settings_key"),
        "system_settings",
        ["key"],
        postgresql_nulls_not_distinct=False,
    )
    op.alter_column(
        "system_settings",
        "updated_at",
        existing_type=postgresql.TIMESTAMP(),
        server_default=sa.text("CURRENT_TIMESTAMP"),
        existing_nullable=False,
    )
    op.drop_index(op.f("ix_security_threats_event_id"), table_name="security_threats")
    op.create_index(
        op.f("ix_security_threats_event_id"), "security_threats", ["event_id"], unique=False
    )
    op.create_unique_constraint(
        op.f("uq_security_threats_event_id"),
        "security_threats",
        ["event_id"],
        postgresql_nulls_not_distinct=False,
    )
    op.alter_column(
        "security_threats",
        "detected_at",
        existing_type=postgresql.TIMESTAMP(),
        server_default=sa.text("CURRENT_TIMESTAMP"),
        existing_nullable=False,
    )
    op.alter_column(
        "security_threats",
        "status",
        existing_type=postgresql.ENUM(
            "PENDING", "ACKNOWLEDGED", "RESOLVED", "DISMISSED", name="threatstatus"
        ),
        server_default=sa.text("'PENDING'::threatstatus"),
        existing_nullable=False,
    )
    op.drop_constraint(
        _FK_ROLE_BINDINGS_CREATED_BY,
        "role_bindings",
        type_="foreignkey",
    )
    op.drop_constraint(
        _FK_IDENTITY_LINKS_USER,
        "identity_links",
        type_="foreignkey",
    )
    op.drop_constraint(
        _FK_DELEGATION_REVOCATIONS_REVOKED_BY,
        "delegation_revocations",
        type_="foreignkey",
    )
    op.drop_constraint(
        _FK_DELEGATION_GRANTS_ISSUED_BY,
        "delegation_grants",
        type_="foreignkey",
    )
    op.drop_index(op.f("ix_delegation_grants_issued_at"), table_name="delegation_grants")
    op.alter_column(
        "audit_log",
        "timestamp",
        existing_type=postgresql.TIMESTAMP(),
        server_default=sa.text("CURRENT_TIMESTAMP"),
        existing_nullable=False,
    )
    # ### end Alembic commands ###
