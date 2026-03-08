"""Event bus implementations for the audit pipeline.

``SyncEventBus`` writes directly to the DB session (default).
``RedisStreamEventBus`` publishes to a Redis Stream for async
batch consumption.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

from sqlalchemy.ext.asyncio import AsyncSession

from server.models.audit_schemas import AuditEntry

from .config import STREAM_KEY

logger = logging.getLogger(__name__)
AUDIT_BUS_ERRORS = (AttributeError, OSError, RuntimeError, TypeError, ValueError)


@dataclass(slots=True)
class AuditEventPayload:
    """Normalized payload for audit event publishing."""

    event_type: str
    actor: str | None = None
    tool: str | None = None
    inputs: dict[str, Any] | None = None
    result: str | None = None
    details: dict[str, Any] | None = None
    ip_address: str | None = None


@runtime_checkable
class EventBus(Protocol):
    """Protocol for audit event backends."""

    async def apublish(self, session: AsyncSession | None, payload: AuditEventPayload) -> None:
        """Publish an audit event."""
        raise NotImplementedError

    def is_available(self) -> bool:
        """Return whether the bus can accept events."""
        raise NotImplementedError


class SyncEventBus:
    """Default bus -- adds AuditEntry to the caller's DB session."""

    async def apublish(self, session: AsyncSession | None, payload: AuditEventPayload) -> None:
        """Add an AuditEntry to the session for the caller to commit."""
        if session is None:
            logger.warning(
                "SyncEventBus.apublish called with session=None; event_type=%s will be dropped",
                payload.event_type,
            )
            return

        session.add(
            AuditEntry(
                event_type=payload.event_type,
                actor=payload.actor,
                tool=payload.tool,
                inputs=payload.inputs,
                result=payload.result,
                details=payload.details,
                ip_address=payload.ip_address,
            )
        )

    def is_available(self) -> bool:
        """Return whether the bus is ready to accept events."""
        return True


class RedisStreamEventBus:
    """Publishes audit events to a Redis Stream via XADD."""

    def __init__(self, redis_client: Any) -> None:
        self._redis = redis_client

    async def apublish(self, _session: AsyncSession | None, payload: AuditEventPayload) -> None:
        """Serialize and XADD to the audit stream.

        Fail-open: exceptions are logged but never propagated.
        """
        try:
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            fields: dict[str, str] = {
                "event_type": payload.event_type,
                "timestamp": now.isoformat(),
            }
            if payload.actor is not None:
                fields["actor"] = payload.actor
            if payload.tool is not None:
                fields["tool"] = payload.tool
            if payload.inputs is not None:
                fields["inputs"] = json.dumps(payload.inputs)
            if payload.result is not None:
                fields["result"] = payload.result
            if payload.details is not None:
                fields["details"] = json.dumps(payload.details)
            if payload.ip_address is not None:
                fields["ip_address"] = payload.ip_address

            await self._redis.xadd(STREAM_KEY, fields)
        except AUDIT_BUS_ERRORS:
            logger.exception(
                "RedisStreamEventBus failed to publish event_type=%s",
                payload.event_type,
            )

    def is_available(self) -> bool:
        """Return whether the bus is ready to accept events."""
        return True



# ---------------------------------------------------------------------------
# Bus holder (module-level dict avoids the ``global`` keyword per REQ-SEC-03)
# ---------------------------------------------------------------------------
_BUS_HOLDER: dict[str, EventBus] = {"bus": SyncEventBus()}


def get_event_bus() -> EventBus:
    """Return the currently active event bus."""
    return _BUS_HOLDER["bus"]


def set_event_bus(bus: EventBus) -> None:
    """Replace the active event bus."""
    _BUS_HOLDER["bus"] = bus


async def emit_audit_event(
    session: AsyncSession | None,
    *,
    event_type: str,
    actor: str | None = None,
    tool: str | None = None,
    inputs: dict[str, Any] | None = None,
    result: str | None = None,
    details: dict[str, Any] | None = None,
    ip_address: str | None = None,
) -> None:
    """Single entry-point for all audit event emission."""
    await get_event_bus().apublish(
        session,
        AuditEventPayload(
            event_type=event_type,
            actor=actor,
            tool=tool,
            inputs=inputs,
            result=result,
            details=details,
            ip_address=ip_address,
        ),
    )
