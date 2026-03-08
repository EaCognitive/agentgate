"""
Audit logging data models and types.

Contains all dataclasses, enums, and type definitions for audit logging.
Part of the SOC 2 CC7.2 and HIPAA §164.312(b) compliant audit system.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any


@dataclass
class AuditLogContextWho:
    """Who information for audit context."""

    user_id: str | None = None
    session_id: str | None = None
    agent_id: str | None = None


@dataclass
class AuditLogContextWhat:
    """What information for audit context."""

    resource: str | None = None
    action: str | None = None
    placeholder: str | None = None
    pii_type: str | None = None


@dataclass
class AuditLogContextWhere:
    """Where information for audit context."""

    source_ip: str | None = None
    source_system: str | None = None


@dataclass
class AuditLogContextResult:
    """Result information for audit context."""

    success: bool = True
    error_message: str | None = None


@dataclass
class AuditLogContext:
    """Context parameters for audit event logging."""

    who: AuditLogContextWho = field(default_factory=AuditLogContextWho)
    what: AuditLogContextWhat = field(default_factory=AuditLogContextWhat)
    where: AuditLogContextWhere = field(default_factory=AuditLogContextWhere)
    result: AuditLogContextResult = field(default_factory=AuditLogContextResult)
    metadata: dict[str, Any] | None = None

    @property
    def user_id(self) -> str | None:
        """Get user_id from who."""
        return self.who.user_id

    @property
    def session_id(self) -> str | None:
        """Get session_id from who."""
        return self.who.session_id

    @property
    def agent_id(self) -> str | None:
        """Get agent_id from who."""
        return self.who.agent_id

    @property
    def resource(self) -> str | None:
        """Get resource from what."""
        return self.what.resource

    @property
    def action(self) -> str | None:
        """Get action from what."""
        return self.what.action

    @property
    def placeholder(self) -> str | None:
        """Get placeholder from what."""
        return self.what.placeholder

    @property
    def pii_type(self) -> str | None:
        """Get pii_type from what."""
        return self.what.pii_type

    @property
    def source_ip(self) -> str | None:
        """Get source_ip from where."""
        return self.where.source_ip

    @property
    def source_system(self) -> str | None:
        """Get source_system from where."""
        return self.where.source_system

    @property
    def success(self) -> bool:
        """Get success from result."""
        return self.result.success

    @property
    def error_message(self) -> str | None:
        """Get error_message from result."""
        return self.result.error_message


class AuditEventType(str, Enum):
    """Types of auditable events for PII operations."""

    # PII Vault Operations
    PII_STORE = "pii_store"
    PII_RETRIEVE = "pii_retrieve"
    PII_DELETE = "pii_delete"
    PII_ACCESS_DENIED = "pii_access_denied"
    PII_BULK_RETRIEVE = "pii_bulk_retrieve"
    PII_SESSION_CLEAR = "pii_session_clear"

    # Detection Events
    PII_DETECTED = "pii_detected"
    PII_REDACTED = "pii_redacted"
    PII_REHYDRATED = "pii_rehydrated"

    # Security Events
    INTEGRITY_FAILURE = "integrity_failure"
    DECRYPTION_FAILURE = "decryption_failure"
    ACCESS_DENIED = "access_denied"
    AUTHENTICATION_FAILURE = "auth_failure"

    # System Events
    KEY_ROTATION = "key_rotation"
    SESSION_START = "session_start"
    SESSION_END = "session_end"
    CONFIG_CHANGE = "config_change"


@dataclass
class AuditEventWho:
    """Identity information for audit events."""

    user_id: str | None = None
    session_id: str | None = None
    agent_id: str | None = None


@dataclass
class AuditEventWhat:
    """Action information for audit events."""

    resource: str | None = None
    action: str | None = None
    placeholder: str | None = None
    pii_type: str | None = None


@dataclass
class AuditEventWhere:
    """Location information for audit events."""

    source_ip: str | None = None
    source_system: str | None = None


@dataclass
class AuditEventIntegrity:
    """Integrity verification information for audit events."""

    sequence: int = 0
    previous_hash: str | None = None
    integrity_hash: str | None = None


@dataclass
class AuditEventIdentification:
    """Event identification information."""

    event_id: str
    event_type: AuditEventType
    timestamp: float


@dataclass
class _AuditEventContextInfo:
    """Combined context information for audit events."""

    who: AuditEventWho = field(default_factory=AuditEventWho)
    what: AuditEventWhat = field(default_factory=AuditEventWhat)
    where: AuditEventWhere = field(default_factory=AuditEventWhere)


@dataclass
class _AuditEventResultInfo:
    """Result and metadata information for audit events."""

    success: bool = True
    error_message: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditEvent:  # pylint: disable=too-many-public-methods
    """Immutable audit event record.

    Contains all fields required for SOC 2 and HIPAA compliance.

    Required fields (HIPAA sec.164.312(b)):
    - Who: user_id, session_id, agent_id
    - What: event_type, resource, action
    - When: timestamp
    - Where: source_ip, source_system
    - Result: success, error_message

    Note: The 18 public properties are single-line convenience
    accessors required for HIPAA/SOC 2 field access compatibility.
    Disabling ``too-many-public-methods`` is intentional.
    """

    identification: AuditEventIdentification
    context: _AuditEventContextInfo = field(default_factory=_AuditEventContextInfo)
    result_info: _AuditEventResultInfo = field(default_factory=_AuditEventResultInfo)
    integrity: AuditEventIntegrity = field(default_factory=AuditEventIntegrity)

    @property
    def event_id(self) -> str:
        """Get event_id from identification."""
        return self.identification.event_id

    @property
    def event_type(self) -> AuditEventType:
        """Get event_type from identification."""
        return self.identification.event_type

    @property
    def timestamp(self) -> float:
        """Get timestamp from identification."""
        return self.identification.timestamp

    @property
    def user_id(self) -> str | None:
        """Get user_id from context.who."""
        return self.context.who.user_id

    @property
    def session_id(self) -> str | None:
        """Get session_id from context.who."""
        return self.context.who.session_id

    @property
    def agent_id(self) -> str | None:
        """Get agent_id from context.who."""
        return self.context.who.agent_id

    @property
    def resource(self) -> str | None:
        """Get resource from context.what."""
        return self.context.what.resource

    @property
    def action(self) -> str | None:
        """Get action from context.what."""
        return self.context.what.action

    @property
    def placeholder(self) -> str | None:
        """Get placeholder from context.what."""
        return self.context.what.placeholder

    @property
    def pii_type(self) -> str | None:
        """Get pii_type from context.what."""
        return self.context.what.pii_type

    @property
    def source_ip(self) -> str | None:
        """Get source_ip from context.where."""
        return self.context.where.source_ip

    @property
    def source_system(self) -> str | None:
        """Get source_system from context.where."""
        return self.context.where.source_system

    @property
    def success(self) -> bool:
        """Get success from result_info."""
        return self.result_info.success

    @property
    def error_message(self) -> str | None:
        """Get error_message from result_info."""
        return self.result_info.error_message

    @property
    def metadata(self) -> dict[str, Any]:
        """Get metadata from result_info."""
        return self.result_info.metadata

    @property
    def sequence(self) -> int:
        """Get sequence from integrity."""
        return self.integrity.sequence

    @property
    def previous_hash(self) -> str | None:
        """Get previous_hash from integrity."""
        return self.integrity.previous_hash

    @property
    def integrity_hash(self) -> str | None:
        """Get integrity_hash from integrity."""
        return self.integrity.integrity_hash

    @integrity_hash.setter
    def integrity_hash(self, value: str | None) -> None:
        """Set integrity_hash in integrity."""
        self.integrity.integrity_hash = value

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        d = asdict(self)
        identification = d.pop("identification")
        context = d.pop("context")
        result_info = d.pop("result_info")
        integrity = d.pop("integrity")

        d.update(identification)
        d.update(context.get("who", {}))
        d.update(context.get("what", {}))
        d.update(context.get("where", {}))
        d.update({k: v for k, v in result_info.items() if k != "metadata"})
        if result_info.get("metadata"):
            d["metadata"] = result_info["metadata"]
        d.update(integrity)

        d["event_type"] = self.event_type.value
        d["timestamp_iso"] = datetime.fromtimestamp(self.timestamp).isoformat()
        return d

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), default=str)


__all__ = [
    "AuditLogContextWho",
    "AuditLogContextWhat",
    "AuditLogContextWhere",
    "AuditLogContextResult",
    "AuditLogContext",
    "AuditEventType",
    "AuditEventWho",
    "AuditEventWhat",
    "AuditEventWhere",
    "AuditEventIntegrity",
    "AuditEventIdentification",
    "AuditEvent",
]
