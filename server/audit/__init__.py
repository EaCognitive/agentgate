"""Async audit event pipeline with pluggable backends.

Provides a unified ``emit_audit_event`` helper that all callsites use.
The active backend (sync DB write vs. Redis Stream) is selected at
startup via the ``AUDIT_PIPELINE`` setting.
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

from .config import AuditPipelineMode
from .bus import (
    EventBus,
    SyncEventBus,
    emit_audit_event,
    get_event_bus,
    set_event_bus,
)


def __getattr__(name: str):
    """Lazy-load Redis-specific classes to avoid hard dependency."""
    if name == "RedisStreamEventBus":
        bus_module = import_module("server.audit.bus")
        return getattr(bus_module, name)

    if name == "StreamConsumer":
        consumer_module = import_module("server.audit.consumer")
        return getattr(consumer_module, name)

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


if TYPE_CHECKING:
    from .bus import RedisStreamEventBus
    from .consumer import StreamConsumer


__all__ = [
    "AuditPipelineMode",
    "EventBus",
    "SyncEventBus",
    "RedisStreamEventBus",
    "StreamConsumer",
    "emit_audit_event",
    "get_event_bus",
    "set_event_bus",
]
