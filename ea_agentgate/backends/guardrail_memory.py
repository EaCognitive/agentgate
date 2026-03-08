"""In-memory guardrail backend for development and testing.

Provides MemoryGuardrailBackend, a thread-safe in-memory state machine
that enforces temporal constraints on session transitions.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from ea_agentgate.security.policy import ConstraintType, Policy, PolicyMode

from ea_agentgate.backends.guardrail_types import (
    TransitionResult,
    _ConstraintViolation,
)


def _count_action_events(
    events: list[tuple[float, str]],
    action: str,
    window_start: float,
    now: float,
) -> int:
    """Count events matching a specific action in window."""
    return sum(1 for ts, act in events if window_start <= ts <= now and act == action)


def _count_all_events(
    events: list[tuple[float, str]],
    window_start: float,
    now: float,
) -> int:
    """Count all events within a time window."""
    return sum(1 for ts, _ in events if window_start <= ts <= now)


def _find_transition(
    transitions: list[Any],
    action: str,
) -> str | None:
    """Return next_state for a matching transition."""
    for trans in transitions:
        if trans.action == action:
            next_state = getattr(trans, "next_state", None)
            if isinstance(next_state, str):
                return next_state
            return None
    return None


class MemoryGuardrailBackend:
    """In-memory guardrail backend for development and testing.

    Maintains separate state dictionaries for enforce and shadow
    modes. Thread-safe via an internal reentrant lock.

    Warning:
        Data is lost when the process ends. Use
        RedisGuardrailBackend for production deployments.
    """

    def __init__(self) -> None:
        self._states: dict[str, str] = {}
        self._events: dict[str, list[tuple[float, str]]] = {}
        self._shadow_states: dict[str, str] = {}
        self._shadow_events: dict[str, list[tuple[float, str]]] = {}
        self._lock = threading.RLock()

    def check_and_transition(
        self,
        session_id: str,
        action: str,
        policy: Policy,
        mode: PolicyMode,
    ) -> TransitionResult:
        """Check constraints and apply a state transition.

        Args:
            session_id: Unique session identifier.
            action: The action being attempted.
            policy: Policy defining states and constraints.
            mode: Execution mode (enforce or shadow).

        Returns:
            TransitionResult describing the outcome.
        """
        with self._lock:
            stores, evts = self._select_stores(mode)
            return self._do_transition(
                session_id,
                action,
                policy,
                mode,
                states=stores,
                events=evts,
            )

    def get_session_state(
        self,
        session_id: str,
    ) -> str | None:
        """Retrieve the current state of a session."""
        with self._lock:
            return self._states.get(session_id)

    def reset_session(self, session_id: str) -> None:
        """Remove all state and event data for a session."""
        with self._lock:
            self._states.pop(session_id, None)
            self._events.pop(session_id, None)
            self._shadow_states.pop(session_id, None)
            self._shadow_events.pop(session_id, None)

    def set_session_state(
        self,
        session_id: str,
        state: str,
    ) -> None:
        """Set the state for a session directly.

        Useful for testing and administrative overrides.

        Args:
            session_id: Target session identifier.
            state: The state name to assign.
        """
        with self._lock:
            self._states[session_id] = state

    def inject_event(
        self,
        session_id: str,
        timestamp: float,
        action: str,
    ) -> None:
        """Inject a synthetic event into the session log.

        Useful for testing constraint behaviour without
        performing real transitions.

        Args:
            session_id: Target session identifier.
            timestamp: Unix timestamp of the event.
            action: The action name to record.
        """
        with self._lock:
            self._events.setdefault(
                session_id,
                [],
            ).append((timestamp, action))

    def get_shadow_state(
        self,
        session_id: str,
    ) -> str | None:
        """Retrieve the shadow-mode state for a session.

        Args:
            session_id: Target session identifier.

        Returns:
            The shadow state name, or None if unset.
        """
        with self._lock:
            return self._shadow_states.get(session_id)

    def _select_stores(
        self,
        mode: PolicyMode,
    ) -> tuple[
        dict[str, str],
        dict[str, list[tuple[float, str]]],
    ]:
        """Return state/events dicts for the given mode."""
        if mode == PolicyMode.SHADOW:
            return (
                self._shadow_states,
                self._shadow_events,
            )
        return self._states, self._events

    def _do_transition(
        self,
        session_id: str,
        action: str,
        policy: Policy,
        mode: PolicyMode,
        *,
        states: dict[str, str],
        events: dict[str, list[tuple[float, str]]],
    ) -> TransitionResult:
        """Execute transition logic against given stores."""
        current = states.get(
            session_id,
            policy.initial_state,
        )
        state_def = policy.states.get(current)
        if state_def is None:
            return TransitionResult(
                allowed=False,
                previous_state=current,
                new_state=current,
                reason=(f"State '{current}' not defined in policy"),
                mode=mode.value,
            )

        next_st = _find_transition(
            state_def.transitions,
            action,
        )
        if next_st is None:
            return TransitionResult(
                allowed=False,
                previous_state=current,
                new_state=current,
                reason=(f"No valid transition for action '{action}' in state '{current}'"),
                mode=mode.value,
            )

        violation = self._check_constraints(
            state_def.constraints,
            action,
            events.get(session_id, []),
        )
        if violation is not None:
            return violation.to_result(
                mode.value,
                current,
            )

        now = time.time()
        states[session_id] = next_st
        events.setdefault(session_id, []).append(
            (now, action),
        )
        return TransitionResult(
            allowed=True,
            previous_state=current,
            new_state=next_st,
            reason="Transition allowed",
            mode=mode.value,
        )

    def _check_constraints(
        self,
        constraints: list[Any],
        action: str,
        session_events: list[tuple[float, str]],
    ) -> _ConstraintViolation | None:
        """Evaluate constraints; return violation or None."""
        now = time.time()
        for constraint in constraints:
            if constraint.action != action:
                continue
            window_start = now - constraint.window_seconds
            result = self._evaluate_one(
                constraint,
                action,
                events=session_events,
                window_start=window_start,
                now=now,
            )
            if result is not None:
                return result
        return None

    def _evaluate_one(
        self,
        constraint: Any,
        action: str,
        *,
        events: list[tuple[float, str]],
        window_start: float,
        now: float,
    ) -> _ConstraintViolation | None:
        """Evaluate a single constraint against events."""
        ctype = constraint.constraint_type

        if ctype == ConstraintType.COOLDOWN:
            count = _count_action_events(
                events,
                action,
                window_start,
                now,
            )
            if count > 0:
                return _ConstraintViolation(
                    constraint=f"cooldown:{action}",
                    reason=(constraint.error_msg or f"Cooldown active for action '{action}'"),
                )

        if ctype == ConstraintType.MAX_FREQUENCY:
            count = _count_action_events(
                events,
                action,
                window_start,
                now,
            )
            if count >= constraint.max_count:
                return _ConstraintViolation(
                    constraint=f"max_frequency:{action}",
                    reason=(
                        constraint.error_msg or f"Max frequency exceeded for action '{action}'"
                    ),
                )

        if ctype == ConstraintType.TEMPORAL_EXCLUSION:
            total = _count_all_events(
                events,
                window_start,
                now,
            )
            if total > 0:
                return _ConstraintViolation(
                    constraint=(f"temporal_exclusion:{action}"),
                    reason=(
                        constraint.error_msg or f"Temporal exclusion active for action '{action}'"
                    ),
                )
        return None


__all__ = ["MemoryGuardrailBackend"]
