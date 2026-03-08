"""Tests for guardrail policy validation and loading."""

import json

import pytest

from ea_agentgate.backends.guardrail_backend import MemoryGuardrailBackend
from ea_agentgate.security.policy import (
    ConstraintType,
    FailureMode,
    Policy,
    PolicyMode,
    State,
    TemporalConstraint,
    Transition,
    load_policy_from_dict,
    load_policy_from_file,
    validate_policy,
)
from tests.guardrail_helpers import (
    COOLDOWN_CONSTRAINTS,
    EXCLUSION_CONSTRAINTS,
    MAX_FREQ_CONSTRAINTS,
    make_policy,
)


@pytest.fixture
def _simple_policy():
    """Valid two-state enforce policy."""
    return make_policy()


@pytest.fixture
def _shadow_policy():
    """Valid two-state shadow policy."""
    return make_policy(mode=PolicyMode.SHADOW)


@pytest.fixture
def _cooldown_policy():
    """Policy with 10s cooldown on read_data."""
    return make_policy(constraints=COOLDOWN_CONSTRAINTS)


@pytest.fixture
def _max_freq_policy():
    """Policy with max 3 read_data per 60s."""
    return make_policy(constraints=MAX_FREQ_CONSTRAINTS)


@pytest.fixture
def _exclusion_policy():
    """Policy with 5s temporal exclusion."""
    return make_policy(constraints=EXCLUSION_CONSTRAINTS)


@pytest.fixture
def _mem():
    """Fresh in-memory guardrail backend."""
    return MemoryGuardrailBackend()


class TestPolicyValidation:
    """Tests for policy schema validation and loading."""

    def test_validate_valid_policy(self, _simple_policy):
        """Well-formed policy yields no errors."""
        assert not validate_policy(_simple_policy)

    def test_validate_missing_initial_state(self):
        """Initial state not in states dict is an error."""
        p = Policy(
            policy_id="bad",
            version="1.0.0",
            mode=PolicyMode.ENFORCE,
            initial_state="nonexistent",
            states={"idle": State(name="idle")},
        )
        assert any("nonexistent" in e for e in validate_policy(p))

    def test_validate_invalid_transition_target(self):
        """Transition to unknown state is an error."""
        p = Policy(
            policy_id="bad",
            version="1.0.0",
            mode=PolicyMode.ENFORCE,
            initial_state="idle",
            states={
                "idle": State(
                    name="idle",
                    transitions=[
                        Transition(
                            action="go",
                            next_state="missing",
                        )
                    ],
                )
            },
        )
        assert any("missing" in e for e in validate_policy(p))

    def test_validate_orphan_constraint(self):
        """Constraint with no matching transition is flagged."""
        p = Policy(
            policy_id="bad",
            version="1.0.0",
            mode=PolicyMode.ENFORCE,
            initial_state="idle",
            states={
                "idle": State(
                    name="idle",
                    constraints=[
                        TemporalConstraint(
                            constraint_type=ConstraintType.COOLDOWN,
                            action="orphan",
                            window_seconds=10.0,
                        )
                    ],
                )
            },
        )
        assert any("orphan" in e for e in validate_policy(p))

    def test_validate_multiple_errors(self):
        """Policy with several issues returns all errors."""
        p = Policy(
            policy_id="bad",
            version="1.0.0",
            mode=PolicyMode.ENFORCE,
            initial_state="missing_init",
            states={
                "s1": State(
                    name="s1",
                    transitions=[
                        Transition(
                            action="go",
                            next_state="nowhere",
                        )
                    ],
                    constraints=[
                        TemporalConstraint(
                            constraint_type=ConstraintType.COOLDOWN,
                            action="orphan",
                            window_seconds=5.0,
                        )
                    ],
                )
            },
        )
        assert len(validate_policy(p)) >= 3

    def test_load_from_dict_valid(self):
        """Valid dict produces correct Policy."""
        data = {
            "policy_id": "p1",
            "version": "2.0.0",
            "mode": "enforce",
            "initial_state": "start",
            "states": {
                "start": {
                    "transitions": [
                        {"action": "go", "next_state": "start"},
                    ]
                }
            },
        }
        p = load_policy_from_dict(data)
        assert p.policy_id == "p1"
        assert p.mode == PolicyMode.ENFORCE
        assert "start" in p.states

    def test_load_from_dict_missing_fields(self):
        """Missing required fields raise ValueError."""
        with pytest.raises(ValueError, match="Missing"):
            load_policy_from_dict({"policy_id": "x"})

    def test_load_from_dict_invalid_mode(self):
        """Bad mode string raises ValueError."""
        with pytest.raises(ValueError, match="Invalid mode"):
            load_policy_from_dict(
                {
                    "policy_id": "p1",
                    "version": "1.0.0",
                    "mode": "bad",
                    "initial_state": "s",
                    "states": {},
                }
            )

    def test_load_from_file_valid(self, tmp_path):
        """Policy loaded from valid JSON file."""
        data = {
            "policy_id": "fp",
            "version": "1.0.0",
            "mode": "shadow",
            "initial_state": "init",
            "states": {"init": {"transitions": []}},
        }
        fp = tmp_path / "policy.json"
        fp.write_text(json.dumps(data), encoding="utf-8")
        p = load_policy_from_file(fp)
        assert p.policy_id == "fp"
        assert p.mode == PolicyMode.SHADOW

    def test_load_from_file_missing(self, tmp_path):
        """Non-existent path raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            load_policy_from_file(tmp_path / "nope.json")

    def test_enum_values(self):
        """Verify all enum string values."""
        assert PolicyMode.ENFORCE.value == "enforce"
        assert PolicyMode.SHADOW.value == "shadow"
        assert ConstraintType.COOLDOWN.value == "cooldown"
        assert ConstraintType.MAX_FREQUENCY.value == "max_frequency"
        assert ConstraintType.TEMPORAL_EXCLUSION.value == "temporal_exclusion"
        assert FailureMode.OPEN.value == "open"
        assert FailureMode.CLOSED.value == "closed"
