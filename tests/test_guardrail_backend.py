"""Tests for in-memory guardrail backend."""

from unittest.mock import patch

import pytest

from ea_agentgate.backends.guardrail_backend import MemoryGuardrailBackend
from ea_agentgate.security.policy import PolicyMode
from tests.guardrail_helpers import (
    _TIME_PATH,
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


class TestMemoryGuardrailBackend:
    """Tests for in-memory guardrail backend."""

    def test_initial_state(self, _mem):
        """New session returns None."""
        assert _mem.get_session_state("x") is None

    def test_valid_transition(self, _mem, _simple_policy):
        """Allowed action transitions correctly."""
        r = _mem.check_and_transition(
            "s1",
            "read_data",
            _simple_policy,
            PolicyMode.ENFORCE,
        )
        assert r.allowed is True
        assert r.previous_state == "idle"
        assert r.new_state == "active"

    def test_invalid_transition(self, _mem, _simple_policy):
        """Unregistered action is denied."""
        r = _mem.check_and_transition(
            "s1",
            "nonexistent",
            _simple_policy,
            PolicyMode.ENFORCE,
        )
        assert r.allowed is False
        assert "No valid transition" in r.reason

    @patch(_TIME_PATH)
    def test_cooldown_blocks(
        self,
        mock_time,
        _mem,
        _cooldown_policy,
    ):
        """Cooldown denies repeated action in window."""
        mock_time.time.return_value = 1000.0
        r = _mem.check_and_transition(
            "s1",
            "read_data",
            _cooldown_policy,
            PolicyMode.ENFORCE,
        )
        assert r.allowed is True
        _mem.set_session_state("s1", "idle")
        mock_time.time.return_value = 1001.0
        r2 = _mem.check_and_transition(
            "s1",
            "read_data",
            _cooldown_policy,
            PolicyMode.ENFORCE,
        )
        assert r2.allowed is False
        assert r2.violated_constraint is not None

    @patch(_TIME_PATH)
    def test_cooldown_expires(
        self,
        mock_time,
        _mem,
        _cooldown_policy,
    ):
        """Action allowed after cooldown window passes."""
        mock_time.time.return_value = 1000.0
        _mem.check_and_transition(
            "s1",
            "read_data",
            _cooldown_policy,
            PolicyMode.ENFORCE,
        )
        _mem.set_session_state("s1", "idle")
        mock_time.time.return_value = 1020.0
        r = _mem.check_and_transition(
            "s1",
            "read_data",
            _cooldown_policy,
            PolicyMode.ENFORCE,
        )
        assert r.allowed is True

    @patch(_TIME_PATH)
    def test_max_frequency_under_limit(
        self,
        mock_time,
        _mem,
        _max_freq_policy,
    ):
        """Actions under max_count are permitted."""
        for i in range(2):
            mock_time.time.return_value = 1000.0 + i
            _mem.set_session_state("s1", "idle")
            r = _mem.check_and_transition(
                "s1",
                "read_data",
                _max_freq_policy,
                PolicyMode.ENFORCE,
            )
            assert r.allowed is True

    @patch(_TIME_PATH)
    def test_max_frequency_at_limit(
        self,
        mock_time,
        _mem,
        _max_freq_policy,
    ):
        """Exceeding max_count is denied."""
        for i in range(3):
            mock_time.time.return_value = 1000.0 + i
            _mem.set_session_state("s1", "idle")
            _mem.check_and_transition(
                "s1",
                "read_data",
                _max_freq_policy,
                PolicyMode.ENFORCE,
            )
        mock_time.time.return_value = 1004.0
        _mem.set_session_state("s1", "idle")
        r = _mem.check_and_transition(
            "s1",
            "read_data",
            _max_freq_policy,
            PolicyMode.ENFORCE,
        )
        assert r.allowed is False
        assert "max_frequency" in (r.violated_constraint or "")

    @patch(_TIME_PATH)
    def test_temporal_exclusion(
        self,
        mock_time,
        _mem,
        _exclusion_policy,
    ):
        """Any event in window blocks constrained action."""
        mock_time.time.return_value = 1000.0
        _mem.inject_event("s1", 999.0, "other")
        _mem.set_session_state("s1", "idle")
        r = _mem.check_and_transition(
            "s1",
            "read_data",
            _exclusion_policy,
            PolicyMode.ENFORCE,
        )
        assert r.allowed is False
        assert "temporal_exclusion" in (r.violated_constraint or "")

    def test_session_isolation(self, _mem, _simple_policy):
        """Separate sessions do not interfere."""
        _mem.check_and_transition(
            "a",
            "read_data",
            _simple_policy,
            PolicyMode.ENFORCE,
        )
        assert _mem.get_session_state("a") == "active"
        assert _mem.get_session_state("b") is None

    def test_reset_session(self, _mem, _simple_policy):
        """Reset clears state and events."""
        _mem.check_and_transition(
            "s1",
            "read_data",
            _simple_policy,
            PolicyMode.ENFORCE,
        )
        _mem.reset_session("s1")
        assert _mem.get_session_state("s1") is None

    def test_get_session_state(self, _mem, _simple_policy):
        """Returns current state or None."""
        assert _mem.get_session_state("x") is None
        _mem.check_and_transition(
            "x",
            "read_data",
            _simple_policy,
            PolicyMode.ENFORCE,
        )
        assert _mem.get_session_state("x") == "active"

    def test_shadow_mode_separate_state(
        self,
        _mem,
        _simple_policy,
    ):
        """Shadow mode uses separate state dicts."""
        _mem.check_and_transition(
            "s1",
            "read_data",
            _simple_policy,
            PolicyMode.SHADOW,
        )
        assert _mem.get_shadow_state("s1") == "active"
        assert _mem.get_session_state("s1") is None
