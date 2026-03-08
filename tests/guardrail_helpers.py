"""Shared helpers and factories for guardrail tests."""

from ea_agentgate.middleware.base import MiddlewareContext
from ea_agentgate.security.policy import (
    ConstraintType,
    Policy,
    PolicyMode,
    State,
    TemporalConstraint,
    Transition,
)
from ea_agentgate.trace import Trace

_TIME_PATH = "ea_agentgate.backends.guardrail_memory.time"


def make_policy(
    mode=PolicyMode.ENFORCE,
    constraints=None,
):
    """Two-state policy: idle -> active -> idle."""
    return Policy(
        policy_id="test-policy",
        version="1.0.0",
        mode=mode,
        initial_state="idle",
        states={
            "idle": State(
                name="idle",
                transitions=[
                    Transition(
                        action="read_data",
                        next_state="active",
                    )
                ],
                constraints=constraints or [],
            ),
            "active": State(
                name="active",
                transitions=[
                    Transition(
                        action="finish",
                        next_state="idle",
                    )
                ],
            ),
        },
    )


def make_ctx(
    tool="read_data",
    agent_id="agent-1",
    session_id="sess-1",
):
    """Build a MiddlewareContext for tests."""
    trace = Trace(tool=tool)
    trace.start()
    return MiddlewareContext(
        tool=tool,
        inputs={},
        trace=trace,
        agent_id=agent_id,
        session_id=session_id,
    )


COOLDOWN_CONSTRAINTS = [
    TemporalConstraint(
        constraint_type=ConstraintType.COOLDOWN,
        action="read_data",
        window_seconds=10.0,
    )
]
MAX_FREQ_CONSTRAINTS = [
    TemporalConstraint(
        constraint_type=ConstraintType.MAX_FREQUENCY,
        action="read_data",
        window_seconds=60.0,
        max_count=3,
    )
]
EXCLUSION_CONSTRAINTS = [
    TemporalConstraint(
        constraint_type=ConstraintType.TEMPORAL_EXCLUSION,
        action="read_data",
        window_seconds=5.0,
    )
]
