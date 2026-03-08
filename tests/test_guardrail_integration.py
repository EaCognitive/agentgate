"""Tests for guardrail middleware, agent integration, async, and Redis."""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from ea_agentgate.agent import Agent
from ea_agentgate.backends.guardrail_backend import (
    MemoryGuardrailBackend,
    RedisGuardrailBackend,
    TransitionResult,
)
from ea_agentgate.exceptions import GuardrailViolationError
from ea_agentgate.middleware.base import Middleware
from ea_agentgate.middleware.guardrail import StatefulGuardrail
from ea_agentgate.security.policy import (
    FailureMode,
    PolicyMode,
)
from ea_agentgate.trace import TraceStatus
from tests.guardrail_helpers import (
    COOLDOWN_CONSTRAINTS,
    EXCLUSION_CONSTRAINTS,
    MAX_FREQ_CONSTRAINTS,
    make_ctx,
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


class TestStatefulGuardrailMiddleware:
    """Tests for the StatefulGuardrail middleware."""

    def _gw(self, pol, **kw):
        """Shorthand guardrail constructor."""
        kw.setdefault("backend", MemoryGuardrailBackend())
        return StatefulGuardrail(policy=pol, **kw)

    def test_enforce_allows_valid(self, _simple_policy):
        """Valid transition passes."""
        c = make_ctx()
        self._gw(_simple_policy).before(c)
        assert c.metadata["guardrail_result"]["allowed"]

    def test_enforce_blocks_invalid(self, _simple_policy):
        """Invalid transition raises violation."""
        with pytest.raises(GuardrailViolationError):
            self._gw(_simple_policy).before(
                make_ctx(tool="bad"),
            )

    def test_shadow_logs_violation(self, _shadow_policy):
        """Shadow mode logs but does not raise."""
        c = make_ctx(tool="bad")
        self._gw(_shadow_policy).before(c)
        assert (
            c.metadata.get(
                "guardrail_shadow_violation",
            )
            is True
        )

    def test_fail_closed_on_backend_error(
        self,
        _simple_policy,
    ):
        """Backend error raises violation (fail-closed)."""
        be = MagicMock()
        be.check_and_transition.side_effect = OSError("x")
        gw = self._gw(
            _simple_policy,
            backend=be,
            failure_mode=FailureMode.CLOSED,
        )
        with pytest.raises(GuardrailViolationError) as ei:
            gw.before(make_ctx())
        assert ei.value.__cause__ is not None

    def test_fail_open_on_backend_error(
        self,
        _simple_policy,
    ):
        """Backend error allows through (fail-open)."""
        be = MagicMock()
        be.check_and_transition.side_effect = OSError("x")
        gw = self._gw(
            _simple_policy,
            backend=be,
            failure_mode=FailureMode.OPEN,
        )
        c = make_ctx()
        gw.before(c)
        assert "guardrail_backend_error" in c.metadata

    def test_session_id_fallback_to_agent_id(
        self,
        _simple_policy,
    ):
        """When session_id is None, agent_id is used."""
        be = MemoryGuardrailBackend()
        gw = self._gw(_simple_policy, backend=be)
        gw.before(make_ctx(session_id=None, agent_id="ag"))
        assert be.get_session_state("ag") == "active"

    def test_session_id_fallback_to_default(
        self,
        _simple_policy,
    ):
        """When both IDs are None, 'default' is used."""
        be = MemoryGuardrailBackend()
        gw = self._gw(_simple_policy, backend=be)
        gw.before(make_ctx(session_id=None, agent_id=None))
        assert be.get_session_state("default") == "active"

    def test_mode_override(self, _simple_policy):
        """Constructor mode overrides policy mode."""
        c = make_ctx(tool="bad")
        self._gw(
            _simple_policy,
            mode=PolicyMode.SHADOW,
        ).before(c)
        assert (
            c.metadata.get(
                "guardrail_shadow_violation",
            )
            is True
        )

    def test_policy_from_file_path(self, tmp_path):
        """File path string loads policy correctly."""
        data = {
            "policy_id": "fp",
            "version": "1.0.0",
            "mode": "enforce",
            "initial_state": "idle",
            "states": {
                "idle": {
                    "transitions": [
                        {"action": "go", "next_state": "idle"},
                    ]
                }
            },
        }
        fp = tmp_path / "p.json"
        fp.write_text(json.dumps(data), encoding="utf-8")
        c = make_ctx(tool="go")
        StatefulGuardrail(
            policy=str(fp),
            backend=MemoryGuardrailBackend(),
        ).before(c)
        assert c.metadata["guardrail_result"]["allowed"]

    def test_guardrail_result_in_metadata(
        self,
        _simple_policy,
    ):
        """Metadata has expected guardrail result keys."""
        c = make_ctx()
        self._gw(_simple_policy).before(c)
        expected = {
            "allowed",
            "previous_state",
            "new_state",
            "reason",
            "mode",
            "violated_constraint",
            "timestamp",
        }
        assert (
            set(
                c.metadata["guardrail_result"].keys(),
            )
            == expected
        )

    def test_trace_block_called_on_violation(
        self,
        _simple_policy,
    ):
        """Trace.block() invoked on denied transition."""
        c = make_ctx(tool="bad")
        with pytest.raises(GuardrailViolationError):
            self._gw(_simple_policy).before(c)
        assert c.trace.status == TraceStatus.BLOCKED

    def test_after_logs_result(self, _simple_policy):
        """after() runs without error."""
        gw = self._gw(_simple_policy)
        c = make_ctx()
        gw.before(c)
        gw.after(c, "ok", None)


class TestGuardrailAgentIntegration:
    """Tests for guardrail integration with Agent."""

    def _agent(self, pol, be=None, sid="t1"):
        """Build an Agent wired with a guardrail."""
        be = be or MemoryGuardrailBackend()
        return Agent(
            middleware=[
                StatefulGuardrail(
                    policy=pol,
                    backend=be,
                )
            ],
            session_id=sid,
        ), be

    def test_agent_allows_valid_sequence(
        self,
        _simple_policy,
    ):
        """Agent permits valid tool call."""
        ag, _ = self._agent(_simple_policy, sid="i1")
        ag.register_tool("read_data", lambda: "data")
        assert ag.call("read_data") == "data"

    def test_agent_blocks_invalid_sequence(
        self,
        _simple_policy,
    ):
        """Agent blocks tool with no valid transition."""
        ag, _ = self._agent(_simple_policy, sid="i2")
        ag.register_tool("write_data", lambda: "w")
        with pytest.raises(GuardrailViolationError):
            ag.call("write_data")

    def test_agent_shadow_mode(self, _shadow_policy):
        """Shadow mode does not block."""
        ag, _ = self._agent(_shadow_policy, sid="i3")
        ag.register_tool("write_data", lambda: "w")
        assert ag.call("write_data") == "w"

    def test_multi_middleware_stack(self, _simple_policy):
        """Guardrail works with other middleware."""

        class _Recorder(Middleware):
            """Records tool names."""

            def __init__(self):
                super().__init__()
                self.seen = []

            def before(self, ctx):
                """Record."""
                self.seen.append(ctx.tool)

        rec = _Recorder()
        be = MemoryGuardrailBackend()
        ag = Agent(
            middleware=[
                rec,
                StatefulGuardrail(
                    policy=_simple_policy,
                    backend=be,
                ),
            ],
            session_id="i4",
        )
        ag.register_tool("read_data", lambda: "d")
        ag.call("read_data")
        assert rec.seen == ["read_data"]

    def test_state_persists_across_calls(
        self,
        _simple_policy,
    ):
        """Multiple calls maintain state."""
        ag, be = self._agent(_simple_policy, sid="i5")
        ag.register_tool("read_data", lambda: "d")
        ag.register_tool("finish", lambda: "done")
        ag.call("read_data")
        assert be.get_session_state("i5") == "active"
        ag.call("finish")
        assert be.get_session_state("i5") == "idle"


class TestGuardrailAsync:
    """Tests for async guardrail operations."""

    @pytest.mark.asyncio
    async def test_abefore_with_async_backend(
        self,
        _simple_policy,
    ):
        """abefore uses async_backend when set."""
        abe = AsyncMock()
        abe.acheck_and_transition.return_value = TransitionResult(
            allowed=True,
            previous_state="idle",
            new_state="active",
            reason="ok",
            mode="enforce",
        )
        gw = StatefulGuardrail(
            policy=_simple_policy,
            backend=MemoryGuardrailBackend(),
            async_backend=abe,
        )
        await gw.abefore(make_ctx())
        abe.acheck_and_transition.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_abefore_fallback_to_sync(
        self,
        _simple_policy,
    ):
        """No async backend falls back to sync."""
        gw = StatefulGuardrail(
            policy=_simple_policy,
            backend=MemoryGuardrailBackend(),
        )
        c = make_ctx()
        await gw.abefore(c)
        assert c.metadata["guardrail_result"]["allowed"]

    def test_is_async_native_true(self, _simple_policy):
        """True with async backend."""
        gw = StatefulGuardrail(
            policy=_simple_policy,
            backend=MemoryGuardrailBackend(),
            async_backend=AsyncMock(),
        )
        assert gw.is_async_native() is True

    def test_is_async_native_false(self, _simple_policy):
        """False without async backend."""
        gw = StatefulGuardrail(
            policy=_simple_policy,
            backend=MemoryGuardrailBackend(),
        )
        assert gw.is_async_native() is False

    @pytest.mark.asyncio
    async def test_agent_acall_with_guardrail(
        self,
        _simple_policy,
    ):
        """Async agent call works."""
        ag = Agent(
            middleware=[
                StatefulGuardrail(
                    policy=_simple_policy,
                    backend=MemoryGuardrailBackend(),
                )
            ],
            session_id="a1",
        )
        ag.register_tool("read_data", lambda: "async-d")
        result = await ag.acall("read_data")
        assert result == "async-d"


class TestRedisGuardrailBackend:
    """Tests for Redis-backed guardrail backend."""

    @pytest.fixture
    def _redis_client(self):
        """Fake Redis client via fakeredis."""
        fakeredis = pytest.importorskip("fakeredis")
        return fakeredis.FakeRedis()

    @pytest.fixture
    def _rbe(self, _redis_client):
        """RedisGuardrailBackend with fake client."""
        return RedisGuardrailBackend(client=_redis_client)

    def test_initial_state(self, _rbe):
        """New session returns None."""
        assert _rbe.get_session_state("r-new") is None

    def test_valid_transition(self, _rbe, _simple_policy):
        """Allowed transition via Lua script."""
        r = _rbe.check_and_transition(
            "r1",
            "read_data",
            _simple_policy,
            PolicyMode.ENFORCE,
        )
        assert r.allowed is True
        assert r.new_state == "active"

    def test_invalid_transition(self, _rbe, _simple_policy):
        """Denied when no matching transition."""
        r = _rbe.check_and_transition(
            "r1",
            "bad",
            _simple_policy,
            PolicyMode.ENFORCE,
        )
        assert r.allowed is False
        assert "No valid transition" in r.reason

    def test_cooldown_constraint(
        self,
        _rbe,
        _cooldown_policy,
    ):
        """Lua script enforces cooldown."""
        r1 = _rbe.check_and_transition(
            "rcd",
            "read_data",
            _cooldown_policy,
            PolicyMode.ENFORCE,
        )
        assert r1.allowed is True
        pfx = _rbe.key_prefix
        _rbe.client.set(
            f"{pfx}sess:rcd:state",
            "idle",
        )
        r2 = _rbe.check_and_transition(
            "rcd",
            "read_data",
            _cooldown_policy,
            PolicyMode.ENFORCE,
        )
        assert r2.allowed is False

    def test_reset_session(self, _rbe, _simple_policy):
        """Reset deletes session keys."""
        _rbe.check_and_transition(
            "rst",
            "read_data",
            _simple_policy,
            PolicyMode.ENFORCE,
        )
        assert _rbe.get_session_state("rst") is not None
        _rbe.reset_session("rst")
        assert _rbe.get_session_state("rst") is None

    def test_shadow_mode_keys(
        self,
        _rbe,
        _redis_client,
        _simple_policy,
    ):
        """Shadow mode uses separate key prefix."""
        _rbe.check_and_transition(
            "rsh",
            "read_data",
            _simple_policy,
            PolicyMode.SHADOW,
        )
        pfx = _rbe.key_prefix
        assert (
            _redis_client.get(
                f"{pfx}shadow:sess:rsh:state",
            )
            is not None
        )
        assert (
            _redis_client.get(
                f"{pfx}sess:rsh:state",
            )
            is None
        )
