"""
Policy schema for stateful temporal guardrails.

Provides declarative policy definitions for session state machines with:
- Finite state machine transitions
- Temporal constraints (cooldowns, frequency limits, exclusions)
- Policy validation with comprehensive error reporting
- JSON file loading with proper exception chaining
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from ea_agentgate.security.policy_io import load_policy_json


# =============================================================================
# Enumerations
# =============================================================================


class PolicyMode(str, Enum):
    """Execution mode for guardrail policies."""

    ENFORCE = "enforce"
    SHADOW = "shadow"


class ConstraintType(str, Enum):
    """Types of temporal constraints."""

    COOLDOWN = "cooldown"
    MAX_FREQUENCY = "max_frequency"
    TEMPORAL_EXCLUSION = "temporal_exclusion"


class FailureMode(str, Enum):
    """Backend failure handling mode."""

    OPEN = "open"
    CLOSED = "closed"


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class TemporalConstraint:
    """A temporal constraint on an action within a state.

    Args:
        constraint_type: The type of temporal constraint.
        action: The action this constraint applies to.
        window_seconds: Time window in seconds for the constraint.
        max_count: Maximum allowed occurrences within the window.
        error_msg: Custom error message when constraint is violated.
    """

    constraint_type: ConstraintType
    action: str
    window_seconds: float
    max_count: int = 1
    error_msg: str = ""


@dataclass
class Transition:
    """A valid state transition triggered by an action.

    Args:
        action: The action that triggers this transition.
        next_state: The target state after the transition.
        description: Human-readable description of the transition.
    """

    action: str
    next_state: str
    description: str = ""


@dataclass
class State:
    """A state in the session state machine.

    Args:
        name: Unique identifier for this state.
        transitions: Valid transitions from this state.
        constraints: Temporal constraints active in this state.
        description: Human-readable description of the state.
    """

    name: str
    transitions: list[Transition] = field(default_factory=list)
    constraints: list[TemporalConstraint] = field(default_factory=list)
    description: str = ""


@dataclass
class Policy:
    """Complete guardrail policy defining states, transitions, and constraints.

    Args:
        policy_id: Unique identifier for this policy.
        version: Semantic version string for the policy.
        mode: Execution mode (enforce or shadow).
        initial_state: Name of the starting state.
        states: Mapping of state names to State objects.
        description: Human-readable description of the policy.
        session_ttl: Session time-to-live in seconds.
    """

    policy_id: str
    version: str
    mode: PolicyMode
    initial_state: str
    states: dict[str, State] = field(default_factory=dict)
    description: str = ""
    session_ttl: int = 86400


# =============================================================================
# Validation
# =============================================================================


def validate_policy(policy: Policy) -> list[str]:
    """Validate a policy and return all discovered errors.

    Performs the following checks:
    - The initial_state must reference an existing state.
    - All transition targets must reference existing states.
    - Constraint actions must match a transition action in the
      same state (no orphan constraints).

    Args:
        policy: The Policy object to validate.

    Returns:
        A list of error message strings. An empty list indicates
        the policy is valid.
    """
    errors: list[str] = []

    if not policy.states:
        errors.append(f"Initial state '{policy.initial_state}' not found in states")
        return errors

    # Check initial_state exists
    if policy.initial_state not in policy.states:
        errors.append(f"Initial state '{policy.initial_state}' not found in states")

    # Check all transition targets exist
    for state_name, state in policy.states.items():
        for transition in state.transitions:
            if transition.next_state not in policy.states:
                errors.append(
                    f"State '{state_name}' has transition "
                    f"to unknown state "
                    f"'{transition.next_state}'"
                )

    # Check for orphan constraints
    for state_name, state in policy.states.items():
        transition_actions = {t.action for t in state.transitions}
        for constraint in state.constraints:
            if constraint.action not in transition_actions:
                errors.append(
                    f"State '{state_name}' has constraint "
                    f"on action '{constraint.action}' "
                    f"which has no matching transition"
                )

    return errors


# =============================================================================
# Deserialization Helpers
# =============================================================================


def _parse_enum_value(
    enum_cls: type[Enum],
    raw_value: Any,
    field_name: str,
) -> Any:
    """Parse an enum from its string value.

    Args:
        enum_cls: The Enum class to parse into.
        raw_value: The raw value from the input dict.
        field_name: Name of the field for error messages.

    Returns:
        The parsed enum member.

    Raises:
        ValueError: If the value is not a valid member.
    """
    if isinstance(raw_value, enum_cls):
        return raw_value

    valid_values = [m.value for m in enum_cls]
    for member in enum_cls:
        if member.value == raw_value:
            return member

    raise ValueError(f"Invalid {field_name}: '{raw_value}'. Must be one of {valid_values}")


def _parse_constraint(
    raw: dict[str, Any],
    index: int,
    state_name: str,
) -> TemporalConstraint:
    """Parse a single temporal constraint from a dict.

    Args:
        raw: Raw constraint dictionary.
        index: Index of the constraint in the list.
        state_name: Name of the parent state for error context.

    Returns:
        A TemporalConstraint instance.

    Raises:
        ValueError: If required fields are missing or invalid.
    """
    prefix = f"State '{state_name}', constraint[{index}]"

    if "constraint_type" not in raw:
        raise ValueError(f"{prefix}: missing 'constraint_type'")
    if "action" not in raw:
        raise ValueError(f"{prefix}: missing 'action'")
    if "window_seconds" not in raw:
        raise ValueError(f"{prefix}: missing 'window_seconds'")

    constraint_type = _parse_enum_value(
        ConstraintType,
        raw["constraint_type"],
        f"{prefix} constraint_type",
    )

    return TemporalConstraint(
        constraint_type=constraint_type,
        action=str(raw["action"]),
        window_seconds=float(raw["window_seconds"]),
        max_count=int(raw.get("max_count", 1)),
        error_msg=str(raw.get("error_msg", "")),
    )


def _parse_transition(
    raw: dict[str, Any],
    index: int,
    state_name: str,
) -> Transition:
    """Parse a single transition from a dict.

    Args:
        raw: Raw transition dictionary.
        index: Index of the transition in the list.
        state_name: Name of the parent state for error context.

    Returns:
        A Transition instance.

    Raises:
        ValueError: If required fields are missing.
    """
    prefix = f"State '{state_name}', transition[{index}]"

    if "action" not in raw:
        raise ValueError(f"{prefix}: missing 'action'")
    if "next_state" not in raw:
        raise ValueError(f"{prefix}: missing 'next_state'")

    return Transition(
        action=str(raw["action"]),
        next_state=str(raw["next_state"]),
        description=str(raw.get("description", "")),
    )


def _parse_state(
    name: str,
    raw: dict[str, Any],
) -> State:
    """Parse a single state from a dict.

    Args:
        name: The state name (dict key).
        raw: Raw state dictionary.

    Returns:
        A State instance.

    Raises:
        ValueError: If nested structures are invalid.
    """
    transitions: list[Transition] = []
    raw_transitions = raw.get("transitions", [])
    for idx, raw_transition in enumerate(raw_transitions):
        transitions.append(_parse_transition(raw_transition, idx, name))

    constraints: list[TemporalConstraint] = []
    raw_constraints = raw.get("constraints", [])
    for idx, raw_constraint in enumerate(raw_constraints):
        constraints.append(_parse_constraint(raw_constraint, idx, name))

    return State(
        name=name,
        transitions=transitions,
        constraints=constraints,
        description=str(raw.get("description", "")),
    )


# =============================================================================
# Public Loaders
# =============================================================================


def load_policy_from_dict(data: dict[str, Any]) -> Policy:
    """Deserialize a dictionary into a Policy object.

    Manually parses all nested structures and enum values
    without using eval or exec. Provides descriptive error
    messages for invalid or missing fields.

    Args:
        data: Dictionary conforming to the policy JSON schema.

    Returns:
        A fully constructed Policy instance.

    Raises:
        ValueError: If required fields are missing or values
            are invalid.
    """
    if not data:
        raise ValueError("Policy data must not be empty")

    # Validate required top-level fields
    required_fields = [
        "policy_id",
        "version",
        "mode",
        "initial_state",
    ]
    for req_field in required_fields:
        if req_field not in data:
            raise ValueError(f"Missing required field: '{req_field}'")

    mode = _parse_enum_value(PolicyMode, data["mode"], "mode")

    # Parse states
    states: dict[str, State] = {}
    raw_states = data.get("states", {})
    if not isinstance(raw_states, dict):
        raise ValueError("'states' must be a mapping of state names to state objects")

    for state_name, raw_state in raw_states.items():
        if not isinstance(raw_state, dict):
            raise ValueError(
                f"State '{state_name}' must be a mapping, got {type(raw_state).__name__}"
            )
        states[state_name] = _parse_state(state_name, raw_state)

    return Policy(
        policy_id=str(data["policy_id"]),
        version=str(data["version"]),
        mode=mode,
        initial_state=str(data["initial_state"]),
        states=states,
        description=str(data.get("description", "")),
        session_ttl=int(data.get("session_ttl", 86400)),
    )


def load_policy_from_file(path: str | Path) -> Policy:
    """Load a policy from a JSON file.

    Reads the file, parses the JSON content, and delegates
    to load_policy_from_dict for deserialization.

    Args:
        path: Path to the JSON policy file.

    Returns:
        A fully constructed Policy instance.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the JSON content is invalid or does
            not conform to the policy schema.
    """
    file_path, data = load_policy_json(path)

    try:
        return load_policy_from_dict(data)
    except ValueError as exc:
        raise ValueError(f"Invalid policy in '{file_path}': {exc}") from exc


__all__ = [
    "PolicyMode",
    "ConstraintType",
    "FailureMode",
    "TemporalConstraint",
    "Transition",
    "State",
    "Policy",
    "validate_policy",
    "load_policy_from_dict",
    "load_policy_from_file",
]
