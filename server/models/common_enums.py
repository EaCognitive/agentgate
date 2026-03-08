"""Shared enums for database models and domain models.

This module provides enums that are referenced across the codebase
to maintain a single source of truth for enumeration values.
"""

from enum import Enum

from ea_agentgate.security.access_control import Permission as PIIPermission


class TraceStatus(str, Enum):
    """Enum for tool trace execution lifecycle states.

    Shared between ea_agentgate.trace.TraceStatus and server.models.trace_schemas.TraceStatus
    to maintain consistency across the application.
    """

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"
    AWAITING_APPROVAL = "awaiting_approval"
    DENIED = "denied"
    COMPENSATED = "compensated"
__all__ = ["TraceStatus", "PIIPermission"]
