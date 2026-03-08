"""Redis-backed guardrail backends for production deployments.

Provides RedisGuardrailBackend (synchronous) and
AsyncRedisGuardrailBackend (asynchronous) implementations that use
Lua scripting for atomic check-and-transition operations.
"""

from __future__ import annotations

import json
import time
from typing import Any

from ea_agentgate.security.policy import Policy, PolicyMode

from ea_agentgate.backends.guardrail_types import TransitionResult


# ================================================================
# Lua Script for Atomic Redis Transitions
# ================================================================

_LUA_GUARDRAIL_TRANSITION = """
local current_state = redis.call('GET', KEYS[1])
if not current_state then current_state = ARGV[1] end

local action = ARGV[2]
local transitions = cjson.decode(ARGV[3])
local constraints = cjson.decode(ARGV[4])
local now = tonumber(ARGV[5])
local ttl = tonumber(ARGV[6])

local next_state = nil
for _, t in ipairs(transitions) do
    if t.action == action then
        next_state = t.next_state
        break
    end
end

if not next_state then
    return cjson.encode({allowed=false,
        reason="No valid transition for action '"
            .. action .. "' in state '" .. current_state .. "'",
        previous_state=current_state, new_state=current_state})
end

local function count_action_events(evts, act)
    local c = 0
    for _, ev in ipairs(evts) do
        local sep = string.find(ev, ":", nil, true)
        if sep and string.sub(ev, sep + 1) == act then
            c = c + 1
        end
    end
    return c
end

for _, c in ipairs(constraints) do
    if c.action == action then
        local ws = now - c.window_seconds
        if c.constraint_type == "cooldown" then
            local evts = redis.call(
                'ZRANGEBYSCORE', KEYS[2], ws, now)
            if count_action_events(evts, action) > 0 then
                local msg = c.error_msg
                if not msg or msg == "" then
                    msg = "Cooldown active for action '"
                        .. action .. "'"
                end
                return cjson.encode({allowed=false,
                    reason=msg,
                    previous_state=current_state,
                    new_state=current_state,
                    violated_constraint="cooldown:"
                        .. action})
            end
        elseif c.constraint_type == "max_frequency" then
            local evts = redis.call(
                'ZRANGEBYSCORE', KEYS[2], ws, now)
            if count_action_events(evts, action)
                    >= c.max_count then
                local msg = c.error_msg
                if not msg or msg == "" then
                    msg = "Max frequency exceeded"
                        .. " for action '"
                        .. action .. "'"
                end
                return cjson.encode({allowed=false,
                    reason=msg,
                    previous_state=current_state,
                    new_state=current_state,
                    violated_constraint="max_frequency:"
                        .. action})
            end
        elseif c.constraint_type == "temporal_exclusion" then
            local total = redis.call(
                'ZCOUNT', KEYS[2], ws, now)
            if total > 0 then
                local msg = c.error_msg
                if not msg or msg == "" then
                    msg = "Temporal exclusion active"
                        .. " for action '"
                        .. action .. "'"
                end
                return cjson.encode({allowed=false,
                    reason=msg,
                    previous_state=current_state,
                    new_state=current_state,
                    violated_constraint="temporal_exclusion:"
                        .. action})
            end
        end
    end
end

redis.call('SET', KEYS[1], next_state)
redis.call('EXPIRE', KEYS[1], ttl)
local event_member = tostring(now) .. ":" .. action
redis.call('ZADD', KEYS[2], now, event_member)
redis.call('EXPIRE', KEYS[2], ttl)
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now - ttl)

return cjson.encode({allowed=true,
    reason="Transition allowed",
    previous_state=current_state,
    new_state=next_state})
"""


# ================================================================
# Redis Serialization Helpers
# ================================================================


def _serialize_transitions(transitions: list[Any]) -> str:
    """Serialize transitions to JSON for the Lua script."""
    return json.dumps(
        [
            {
                "action": t.action,
                "next_state": t.next_state,
            }
            for t in transitions
        ]
    )


def _serialize_constraints(
    constraints: list[Any],
    action: str,
) -> str:
    """Serialize matching constraints to JSON for Lua."""
    return json.dumps(
        [
            {
                "constraint_type": c.constraint_type.value,
                "action": c.action,
                "window_seconds": c.window_seconds,
                "max_count": c.max_count,
                "error_msg": c.error_msg,
            }
            for c in constraints
            if c.action == action
        ]
    )


def _build_redis_keys(
    prefix: str,
    session_id: str,
    mode: PolicyMode,
) -> tuple[str, str]:
    """Build Redis keys for state and events."""
    if mode == PolicyMode.SHADOW:
        base = f"{prefix}shadow:sess:{session_id}"
        return f"{base}:state", f"{base}:events"
    base = f"{prefix}sess:{session_id}"
    return f"{base}:state", f"{base}:events"


def _parse_lua_result(
    raw_result: Any,
    mode: PolicyMode,
) -> TransitionResult:
    """Parse the JSON result returned by the Lua script."""
    if isinstance(raw_result, bytes):
        raw_result = raw_result.decode("utf-8")
    data = json.loads(raw_result)
    return TransitionResult(
        allowed=bool(data.get("allowed", False)),
        previous_state=str(
            data.get("previous_state", ""),
        ),
        new_state=str(data.get("new_state", "")),
        reason=str(data.get("reason", "")),
        mode=mode.value,
        violated_constraint=data.get(
            "violated_constraint",
        ),
    )


def _resolve_state(
    client_value: Any,
    initial_state: str,
) -> str:
    """Decode a Redis GET result into a state name."""
    if client_value is None:
        return initial_state
    if isinstance(client_value, bytes):
        return client_value.decode("utf-8")
    return str(client_value)


def _state_not_found(
    state_name: str,
    mode: PolicyMode,
) -> TransitionResult:
    """Build a result for an undefined state."""
    return TransitionResult(
        allowed=False,
        previous_state=state_name,
        new_state=state_name,
        reason=(f"State '{state_name}' not defined in policy"),
        mode=mode.value,
    )


def _call_lua(
    script: Any,
    state_key: str,
    events_key: str,
    policy: Policy,
    action: str,
    *,
    transitions_json: str,
    constraints_json: str,
    ttl: int,
) -> Any:
    """Build the args list and call the Lua script (sync)."""
    now = time.time()
    return script(
        keys=[state_key, events_key],
        args=[
            policy.initial_state,
            action,
            transitions_json,
            constraints_json,
            str(now),
            str(ttl),
        ],
    )


# ================================================================
# Redis Sync Implementation
# ================================================================


class RedisGuardrailBackend:
    """Redis-backed guardrail backend for production.

    Uses a Lua script registered via ``register_script()`` for
    atomic check-and-transition operations. Events are stored
    in sorted sets with score equal to the event timestamp.
    """

    def __init__(
        self,
        client: Any,
        key_prefix: str = "agentgate:guardrail:",
        ttl: int = 86400,
    ) -> None:
        self.client = client
        self.key_prefix = key_prefix
        self._ttl = ttl
        self._script = self.client.register_script(
            _LUA_GUARDRAIL_TRANSITION,
        )

    def check_and_transition(
        self,
        session_id: str,
        action: str,
        policy: Policy,
        mode: PolicyMode,
    ) -> TransitionResult:
        """Check constraints and apply a state transition."""
        state_key, events_key = _build_redis_keys(
            self.key_prefix,
            session_id,
            mode,
        )
        state_name = _resolve_state(
            self.client.get(state_key),
            policy.initial_state,
        )
        state_def = policy.states.get(state_name)
        if state_def is None:
            return _state_not_found(state_name, mode)

        raw = _call_lua(
            self._script,
            state_key,
            events_key,
            policy,
            action,
            transitions_json=_serialize_transitions(
                state_def.transitions,
            ),
            constraints_json=_serialize_constraints(
                state_def.constraints,
                action,
            ),
            ttl=self._ttl,
        )
        return _parse_lua_result(raw, mode)

    def get_session_state(
        self,
        session_id: str,
    ) -> str | None:
        """Retrieve the current state of a session."""
        key = f"{self.key_prefix}sess:{session_id}:state"
        value = self.client.get(key)
        if value is None:
            return None
        if isinstance(value, bytes):
            return value.decode("utf-8")
        return str(value)

    def reset_session(self, session_id: str) -> None:
        """Remove all state and event data for a session."""
        sid = session_id
        pfx = self.key_prefix
        self.client.delete(
            f"{pfx}sess:{sid}:state",
            f"{pfx}sess:{sid}:events",
            f"{pfx}shadow:sess:{sid}:state",
            f"{pfx}shadow:sess:{sid}:events",
        )


# ================================================================
# Redis Async Implementation
# ================================================================


class AsyncRedisGuardrailBackend:
    """Async Redis-backed guardrail backend for production.

    Mirrors RedisGuardrailBackend but uses ``await`` on all
    Redis operations. Designed for ``redis.asyncio``.
    """

    def __init__(
        self,
        client: Any,
        key_prefix: str = "agentgate:guardrail:",
        ttl: int = 86400,
    ) -> None:
        self.client = client
        self.key_prefix = key_prefix
        self._ttl = ttl
        self._script = self.client.register_script(
            _LUA_GUARDRAIL_TRANSITION,
        )

    async def acheck_and_transition(
        self,
        session_id: str,
        action: str,
        policy: Policy,
        mode: PolicyMode,
    ) -> TransitionResult:
        """Async check constraints and apply transition."""
        state_key, events_key = _build_redis_keys(
            self.key_prefix,
            session_id,
            mode,
        )
        state_name = _resolve_state(
            await self.client.get(state_key),
            policy.initial_state,
        )
        state_def = policy.states.get(state_name)
        if state_def is None:
            return _state_not_found(state_name, mode)

        t_json = _serialize_transitions(
            state_def.transitions,
        )
        c_json = _serialize_constraints(
            state_def.constraints,
            action,
        )
        now = time.time()
        raw = await self._script(
            keys=[state_key, events_key],
            args=[
                policy.initial_state,
                action,
                t_json,
                c_json,
                str(now),
                str(self._ttl),
            ],
        )
        return _parse_lua_result(raw, mode)

    async def aget_session_state(
        self,
        session_id: str,
    ) -> str | None:
        """Async retrieve the current state of a session."""
        key = f"{self.key_prefix}sess:{session_id}:state"
        value = await self.client.get(key)
        if value is None:
            return None
        if isinstance(value, bytes):
            return value.decode("utf-8")
        return str(value)

    async def areset_session(
        self,
        session_id: str,
    ) -> None:
        """Async remove all state and event data."""
        sid = session_id
        pfx = self.key_prefix
        await self.client.delete(
            f"{pfx}sess:{sid}:state",
            f"{pfx}sess:{sid}:events",
            f"{pfx}shadow:sess:{sid}:state",
            f"{pfx}shadow:sess:{sid}:events",
        )


__all__ = [
    "RedisGuardrailBackend",
    "AsyncRedisGuardrailBackend",
]
