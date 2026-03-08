"""Trace data structures for tool call tracking."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class TraceStatus(Enum):
    """Status of a traced tool call."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"
    AWAITING_APPROVAL = "awaiting_approval"
    DENIED = "denied"
    COMPENSATED = "compensated"


@dataclass
class TraceTiming:
    """Timing information for a trace."""

    started_at: datetime | None = None
    ended_at: datetime | None = None
    duration_ms: float | None = None
    # Internal timing field (not serialized)
    _start_time: float = field(default=0.0, repr=False, compare=False)


@dataclass
class TraceResult:
    """Result of a traced tool call."""

    output: Any = None
    error: str | None = None
    status: TraceStatus = TraceStatus.PENDING


@dataclass
class TraceContext:
    """Contextual information for a trace."""

    parent_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    cost: float | None = None
    blocked_by: str | None = None
    compensation: str | None = None


@dataclass
class Trace:
    """
    A traced tool call with full context.

    Captures everything about a tool execution for debugging,
    audit trails, and observability.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    tool: str = ""
    inputs: dict[str, Any] = field(default_factory=dict)
    timing: TraceTiming = field(default_factory=TraceTiming)
    result: TraceResult = field(default_factory=TraceResult)
    context: TraceContext = field(default_factory=TraceContext)

    def start(self) -> None:
        """Mark trace as started."""
        self.result.status = TraceStatus.RUNNING
        self.timing.started_at = datetime.now()
        self.timing._start_time = time.perf_counter()  # pylint: disable=protected-access

    def succeed(self, output: Any) -> None:
        """Mark trace as successful."""
        self.result.status = TraceStatus.SUCCESS
        self.result.output = output
        self._finalize()

    def fail(self, error: str) -> None:
        """Mark trace as failed."""
        self.result.status = TraceStatus.FAILED
        self.result.error = error
        self._finalize()

    def block(self, reason: str, middleware: str) -> None:
        """Mark trace as blocked by middleware."""
        self.result.status = TraceStatus.BLOCKED
        self.result.error = reason
        self.context.blocked_by = middleware
        self._finalize()

    def _finalize(self) -> None:
        """Finalize timing."""
        self.timing.ended_at = datetime.now()
        # pylint: disable=protected-access
        if self.timing._start_time > 0:
            self.timing.duration_ms = (time.perf_counter() - self.timing._start_time) * 1000

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "tool": self.tool,
            "inputs": self.inputs,
            "output": self.result.output,
            "status": self.result.status.value,
            "error": self.result.error,
            "blocked_by": self.context.blocked_by,
            "started_at": self.timing.started_at.isoformat() if self.timing.started_at else None,
            "ended_at": self.timing.ended_at.isoformat() if self.timing.ended_at else None,
            "duration_ms": self.timing.duration_ms,
            "cost": self.context.cost,
            "metadata": self.context.metadata,
            "parent_id": self.context.parent_id,
        }

    @property
    def status(self) -> TraceStatus:
        """Return the status of the trace."""
        return self.result.status

    def __repr__(self) -> str:
        return (
            f"Trace({self.tool}, {self.result.status.value}, {self.timing.duration_ms:.1f}ms)"
            if self.timing.duration_ms
            else f"Trace({self.tool}, {self.result.status.value})"
        )
