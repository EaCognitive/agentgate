"""
Compliance audit logging - SOC 2 CC7.2 and HIPAA §164.312(b) compliant.

Provides tamper-evident audit logging with:
- Immutable append-only log structure
- Cryptographic integrity verification
- Required fields for compliance
- Export capabilities for auditors
"""

from __future__ import annotations

import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, TextIO
from collections.abc import Callable

from .audit_models import (
    AuditEvent,
    AuditEventIdentification,
    AuditEventIntegrity,
    AuditEventType,
    AuditEventWhat,
    AuditEventWhere,
    AuditEventWho,
    AuditLogContext,
    AuditLogContextResult,
    AuditLogContextWhat,
    AuditLogContextWhere,
    AuditLogContextWho,
    _AuditEventContextInfo,
    _AuditEventResultInfo,
)
from .integrity import ChainOfCustody, HMACIntegrity


@dataclass
class _AuditLogSecurityConfig:
    """Security configuration for audit logging."""

    integrity_key: bytes
    integrity: HMACIntegrity
    chain: "ChainOfCustody | None" = None


@dataclass
class _AuditLogConfig:
    """Configuration for audit logging."""

    retention_days: int = 2190
    include_chain: bool = True
    max_buffer_size: int = 10000


@dataclass
class _AuditLogIntegrityState:
    """Integrity-related state for audit logging."""

    sequence: int = 0
    previous_hash: str | None = None


@dataclass
class _AuditLogIOState:
    """I/O-related state for audit logging."""

    buffer: list[AuditEvent] = field(default_factory=list)
    file_handle: TextIO | None = None


@dataclass
class _AuditLogState:
    """Mutable state for audit logging."""

    integrity: _AuditLogIntegrityState = field(default_factory=_AuditLogIntegrityState)
    io: _AuditLogIOState = field(default_factory=_AuditLogIOState)
    lock: threading.RLock = field(default_factory=threading.RLock)

    @property
    def sequence(self) -> int:
        """Get sequence from integrity."""
        return self.integrity.sequence

    @sequence.setter
    def sequence(self, value: int) -> None:
        """Set sequence in integrity."""
        self.integrity.sequence = value

    @property
    def previous_hash(self) -> str | None:
        """Get previous_hash from integrity."""
        return self.integrity.previous_hash

    @previous_hash.setter
    def previous_hash(self, value: str | None) -> None:
        """Set previous_hash in integrity."""
        self.integrity.previous_hash = value

    @property
    def buffer(self) -> list[AuditEvent]:
        """Get buffer from io."""
        return self.io.buffer

    @property
    def file_handle(self) -> TextIO | None:
        """Get file_handle from io."""
        return self.io.file_handle

    @file_handle.setter
    def file_handle(self, value: TextIO | None) -> None:
        """Set file_handle in io."""
        self.io.file_handle = value


@dataclass
class _AuditLogDestinationConfig:
    """Destination configuration for audit logging."""

    destination: Path | TextIO | None = None
    file_path: Path | None = None


class ComplianceAuditLog:
    """
    SOC 2 and HIPAA compliant audit logging.

    Features:
    - Tamper-evident logging with HMAC chain
    - Configurable retention periods
    - Multiple output destinations
    - Structured JSON format
    - Compliance-ready export

    Example:
        audit = ComplianceAuditLog(
            integrity_key=generate_key(),
            destination=Path("/var/log/agentgate/audit.jsonl"),
            retention_days=2190,
        )

        audit.log(
            event_type=AuditEventType.PII_STORE,
            user_id="user123",
            session_id="sess456",
            placeholder="<SSN_1>",
            pii_type="SSN",
            success=True,
        )
    """

    def __init__(
        self,
        *,
        integrity_key: bytes | None = None,
        destination: Path | TextIO | None = None,
        callback: Callable[[AuditEvent], None] | None = None,
        retention_days: int = 2190,
        include_chain: bool = True,
    ):
        """
        Initialize compliance audit log.

        Args:
            integrity_key: Key for HMAC integrity (generates if None)
            destination: File path or stream for log output
            callback: Optional callback for each event
            retention_days: Minimum retention period (6 years default for HIPAA)
            include_chain: Include integrity chain (tamper detection)
        """
        key = integrity_key or secrets.token_bytes(32)
        self._security = _AuditLogSecurityConfig(
            integrity_key=key,
            integrity=HMACIntegrity(key),
            chain=ChainOfCustody(key) if include_chain else None,
        )

        self._dest_config = _AuditLogDestinationConfig()
        self._callback = callback
        self._config = _AuditLogConfig(
            retention_days=retention_days,
            include_chain=include_chain,
        )
        self._state = _AuditLogState()

        if isinstance(destination, Path):
            destination.parent.mkdir(parents=True, exist_ok=True)
            self._dest_config.file_path = destination
        elif hasattr(destination, "write"):
            self._state.io.file_handle = destination
        self._dest_config.destination = destination

    def _build_audit_event(
        self,
        event_id: str,
        event_type: AuditEventType,
        timestamp: float,
        context: AuditLogContext,
    ) -> AuditEvent:
        """Build an audit event from context."""
        return AuditEvent(
            identification=AuditEventIdentification(
                event_id=event_id,
                event_type=event_type,
                timestamp=timestamp,
            ),
            context=_AuditEventContextInfo(
                who=AuditEventWho(
                    user_id=context.user_id,
                    session_id=context.session_id,
                    agent_id=context.agent_id,
                ),
                what=AuditEventWhat(
                    resource=context.resource,
                    action=context.action,
                    placeholder=context.placeholder,
                    pii_type=context.pii_type,
                ),
                where=AuditEventWhere(
                    source_ip=context.source_ip,
                    source_system=context.source_system,
                ),
            ),
            result_info=_AuditEventResultInfo(
                success=context.success,
                error_message=context.error_message,
                metadata=context.metadata or {},
            ),
            integrity=AuditEventIntegrity(
                sequence=self._state.sequence,
                previous_hash=self._state.previous_hash,
            ),
        )

    def _log_event(
        self,
        event_type: AuditEventType,
        context: AuditLogContext,
    ) -> AuditEvent:
        """
        Internal method to log an audit event with context.

        Args:
            event_type: Type of event
            context: Grouped event context

        Returns:
            The created AuditEvent
        """
        with self._state.lock:
            self._state.sequence += 1
            timestamp = time.time()
            event_id = self._generate_event_id(timestamp, self._state.sequence)

            event = self._build_audit_event(
                event_id=event_id,
                event_type=event_type,
                timestamp=timestamp,
                context=context,
            )

            event_data = self._serialize_for_hash(event)
            event.integrity_hash = self._security.integrity.sign(event_data)
            self._state.integrity.previous_hash = event.integrity_hash

            if self._security.chain:
                self._security.chain.add_record(event_data)
            self._write_event(event)

            self._state.io.buffer.append(event)
            if len(self._state.io.buffer) > self._config.max_buffer_size:
                self._state.io.buffer.pop(0)

            if self._callback:
                self._callback(event)

            return event

    def log(
        self,
        event_type: AuditEventType,
        *,
        user_id: str | None = None,
        session_id: str | None = None,
        agent_id: str | None = None,
        error_message: str | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> AuditEvent:
        """
        Log an audit event.

        Args:
            event_type: Type of event
            user_id: User performing the action
            session_id: Session identifier
            agent_id: Agent identifier
            error_message: Error details if failed
            metadata: Additional context
            **kwargs: Additional parameters (resource, action, placeholder,
                pii_type, source_ip, source_system, success)

        Returns:
            The created AuditEvent
        """
        context = AuditLogContext(
            who=AuditLogContextWho(
                user_id=user_id,
                session_id=session_id,
                agent_id=agent_id,
            ),
            what=AuditLogContextWhat(
                resource=kwargs.get("resource"),
                action=kwargs.get("action"),
                placeholder=kwargs.get("placeholder"),
                pii_type=kwargs.get("pii_type"),
            ),
            where=AuditLogContextWhere(
                source_ip=kwargs.get("source_ip"),
                source_system=kwargs.get("source_system"),
            ),
            result=AuditLogContextResult(
                success=kwargs.get("success", True),
                error_message=error_message,
            ),
            metadata=metadata,
        )

        return self._log_event(event_type, context)

    def log_pii_store(
        self,
        placeholder: str,
        pii_type: str,
        user_id: str | None = None,
        session_id: str | None = None,
        **kwargs,
    ) -> AuditEvent:
        """Convenience method for PII store events."""
        return self.log(
            event_type=AuditEventType.PII_STORE,
            placeholder=placeholder,
            pii_type=pii_type,
            user_id=user_id,
            session_id=session_id,
            resource="pii_vault",
            action="store",
            **kwargs,
        )

    def log_pii_retrieve(
        self,
        placeholder: str,
        user_id: str | None = None,
        session_id: str | None = None,
        success: bool = True,
        **kwargs,
    ) -> AuditEvent:
        """Convenience method for PII retrieve events."""
        return self.log(
            event_type=AuditEventType.PII_RETRIEVE,
            placeholder=placeholder,
            user_id=user_id,
            session_id=session_id,
            resource="pii_vault",
            action="retrieve",
            success=success,
            **kwargs,
        )

    def log_pii_delete(
        self,
        session_id: str,
        user_id: str | None = None,
        **kwargs,
    ) -> AuditEvent:
        """Convenience method for PII delete events."""
        return self.log(
            event_type=AuditEventType.PII_SESSION_CLEAR,
            session_id=session_id,
            user_id=user_id,
            resource="pii_vault",
            action="clear_session",
            **kwargs,
        )

    def log_access_denied(
        self,
        user_id: str | None,
        resource: str,
        action: str,
        reason: str,
        **kwargs,
    ) -> AuditEvent:
        """Log access denied event."""
        return self.log(
            event_type=AuditEventType.ACCESS_DENIED,
            user_id=user_id,
            resource=resource,
            action=action,
            success=False,
            error_message=reason,
            **kwargs,
        )

    def log_integrity_failure(
        self,
        resource: str,
        details: str,
        **kwargs,
    ) -> AuditEvent:
        """Log integrity verification failure."""
        return self.log(
            event_type=AuditEventType.INTEGRITY_FAILURE,
            resource=resource,
            success=False,
            error_message=details,
            **kwargs,
        )

    def verify_chain(self) -> bool:
        """
        Verify the integrity of the entire audit chain.

        Returns:
            True if chain is intact, False if tampered
        """
        if not self._security.chain:
            return True

        return self._security.chain.verify_chain()

    def get_events(
        self,
        *,
        start_time: float | None = None,
        end_time: float | None = None,
        event_type: AuditEventType | None = None,
        user_id: str | None = None,
        session_id: str | None = None,
        limit: int = 1000,
    ) -> list[AuditEvent]:
        """
        Query events from buffer.

        For production use with large logs, query the log file directly
        or use a dedicated log aggregation system.
        """
        results: list[AuditEvent] = []

        for event in reversed(self._state.io.buffer):
            if len(results) >= limit:
                break

            if start_time and event.timestamp < start_time:
                continue
            if end_time and event.timestamp > end_time:
                continue
            if event_type and event.event_type != event_type:
                continue
            if user_id and event.user_id != user_id:
                continue
            if session_id and event.session_id != session_id:
                continue

            results.append(event)

        return list(reversed(results))

    def export_for_audit(
        self,
        start_time: float | None = None,
        end_time: float | None = None,
        include_verification: bool = True,
    ) -> dict[str, Any]:
        """
        Export audit log for compliance review.

        Returns a structured report suitable for SOC 2/HIPAA auditors.
        """
        events = self.get_events(start_time=start_time, end_time=end_time, limit=100000)

        report = {
            "export_timestamp": datetime.now().isoformat(),
            "export_timestamp_unix": time.time(),
            "period": {
                "start": (datetime.fromtimestamp(start_time).isoformat() if start_time else None),
                "end": datetime.fromtimestamp(end_time).isoformat() if end_time else None,
            },
            "total_events": len(events),
            "retention_policy_days": self._config.retention_days,
            "integrity_chain_enabled": self._config.include_chain,
            "events": [e.to_dict() for e in events],
        }

        if include_verification:
            report["chain_verified"] = self.verify_chain()

        type_counts: dict[str, int] = {}
        for event in events:
            type_name = event.event_type.value
            type_counts[type_name] = type_counts.get(type_name, 0) + 1

        report["event_type_summary"] = type_counts

        success_count = sum(1 for e in events if e.success)
        report["success_rate"] = success_count / len(events) if events else 1.0

        return report

    def close(self):
        """Close file handle if owned."""
        if self._state.io.file_handle and isinstance(self._dest_config.destination, Path):
            self._state.io.file_handle.close()
            self._state.io.file_handle = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def _generate_event_id(self, timestamp: float, sequence: int) -> str:
        """Generate unique event ID."""
        random_part = secrets.token_hex(4)
        return f"evt_{int(timestamp)}_{sequence}_{random_part}"

    def _serialize_for_hash(self, event: AuditEvent) -> str:
        """Serialize event for hashing (excludes integrity_hash)."""
        data = {
            "event_id": event.event_id,
            "event_type": event.event_type.value,
            "timestamp": event.timestamp,
            "user_id": event.user_id,
            "session_id": event.session_id,
            "agent_id": event.agent_id,
            "resource": event.resource,
            "action": event.action,
            "placeholder": event.placeholder,
            "pii_type": event.pii_type,
            "success": event.success,
            "error_message": event.error_message,
            "sequence": event.sequence,
            "previous_hash": event.previous_hash,
        }
        return json.dumps(data, sort_keys=True)

    def _write_event(self, event: AuditEvent):
        """Write event to destination."""
        if self._state.io.file_handle:
            self._state.io.file_handle.write(event.to_json() + "\n")
            self._state.io.file_handle.flush()
        elif self._dest_config.file_path:
            with open(self._dest_config.file_path, "a", encoding="utf-8") as f:
                f.write(event.to_json() + "\n")


__all__ = [
    "AuditEventType",
    "AuditEvent",
    "ComplianceAuditLog",
]
