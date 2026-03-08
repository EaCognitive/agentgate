"""Security policy database schemas for natural language governance.

This module defines SQLModel tables and response models for storing
and managing security policies created via MCP tools or manual input.
"""

from datetime import datetime, timezone
from typing import Any, ClassVar

from sqlalchemy import Column, JSON
from sqlmodel import Field, SQLModel


def utc_now() -> datetime:
    """Return current UTC timestamp without timezone info.

    Returns:
        datetime: Current UTC time as naive datetime.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


class SecurityPolicy(SQLModel, table=True):
    """Security policy table for governance rules.

    Stores versioned security policies with HMAC integrity signatures.
    MCP-created policies are locked by default to prevent tampering.
    Only one policy can be active at a time.
    """

    __tablename__: ClassVar[str] = "security_policies"

    id: int | None = Field(default=None, primary_key=True)
    policy_id: str = Field(index=True, nullable=False, description="UUID identifier for policy")
    version: int = Field(default=1, description="Version number, incremented on updates")
    policy_json: dict[str, Any] = Field(
        sa_column=Column(JSON, nullable=False),
        description="Compiled policy rules as JSON",
    )
    origin: str = Field(description="Policy origin: 'mcp', 'manual', or 'system'")
    created_by_user_id: int | None = Field(
        default=None,
        foreign_key="users.id",
        description="User who created the policy",
    )
    created_at: datetime = Field(default_factory=utc_now, description="Policy creation timestamp")
    hmac_signature: str = Field(description="HMAC-SHA256 of policy_json")
    locked: bool = Field(default=False, description="Whether policy is locked from editing")
    is_active: bool = Field(default=False, description="Whether policy is currently active")
    activated_at: datetime | None = Field(default=None, description="When policy was activated")
    activated_by_user_id: int | None = Field(
        default=None,
        foreign_key="users.id",
        description="User who activated the policy",
    )


class SecurityPolicyRead(SQLModel):
    """Response model for security policy data.

    Used for API responses when querying security policies.
    """

    id: int
    policy_id: str
    version: int
    policy_json: dict[str, Any]
    origin: str
    created_by_user_id: int | None
    created_at: datetime
    hmac_signature: str
    locked: bool
    is_active: bool
    activated_at: datetime | None
    activated_by_user_id: int | None
