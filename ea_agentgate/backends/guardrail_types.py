"""Guardrail type definitions, protocols, and internal helpers.

Provides the TransitionResult dataclass, sync/async backend protocols,
and the internal _ConstraintViolation carrier used by all guardrail
backend implementations.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from ea_agentgate.security.policy import Policy, PolicyMode


@dataclass
class TransitionResult:
    """Result of a guardrail transition check.

    Args:
        allowed: Whether the transition was permitted.
        previous_state: State before the transition attempt.
        new_state: State after (unchanged if denied).
        reason: Human-readable explanation of the outcome.
        mode: Policy mode under which the check ran.
        violated_constraint: Constraint identifier if denied.
        timestamp: Unix timestamp of the check.
    """

    allowed: bool
    previous_state: str
    new_state: str
    reason: str
    mode: str
    violated_constraint: str | None = None
    timestamp: float = field(default_factory=time.time)


@runtime_checkable
class GuardrailBackend(Protocol):
    """Synchronous backend for guardrail state management."""

    def check_and_transition(
        self,
        session_id: str,
        action: str,
        policy: Policy,
        mode: PolicyMode,
    ) -> TransitionResult:
        """Check constraints and apply a state transition."""
        raise NotImplementedError

    def get_session_state(
        self,
        session_id: str,
    ) -> str | None:
        """Retrieve the current state of a session."""
        raise NotImplementedError

    def reset_session(self, session_id: str) -> None:
        """Remove all state and event data for a session."""
        raise NotImplementedError


@runtime_checkable
class AsyncGuardrailBackend(Protocol):
    """Asynchronous backend for guardrail state management."""

    async def acheck_and_transition(
        self,
        session_id: str,
        action: str,
        policy: Policy,
        mode: PolicyMode,
    ) -> TransitionResult:
        """Async check constraints and apply transition."""
        raise NotImplementedError

    async def aget_session_state(
        self,
        session_id: str,
    ) -> str | None:
        """Async retrieve the current state of a session."""
        raise NotImplementedError

    async def areset_session(self, session_id: str) -> None:
        """Async remove all state and event data."""
        raise NotImplementedError


# -- internal helpers --


@dataclass
class _ConstraintViolation:
    """Internal carrier for constraint violation details."""

    constraint: str
    reason: str

    def to_result(
        self,
        mode_value: str,
        current_state: str,
    ) -> TransitionResult:
        """Convert this violation into a TransitionResult."""
        return TransitionResult(
            allowed=False,
            previous_state=current_state,
            new_state=current_state,
            reason=self.reason,
            mode=mode_value,
            violated_constraint=self.constraint,
        )


__all__ = [
    "TransitionResult",
    "GuardrailBackend",
    "AsyncGuardrailBackend",
    "_ConstraintViolation",
]
