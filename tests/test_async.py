"""Async support tests for AgentGate."""

from __future__ import annotations

import asyncio
import json
import sys
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from ea_agentgate.agent import Agent
from ea_agentgate.backends.redis_async import (
    AsyncRedisCacheBackend,
    AsyncRedisPIIVaultBackend,
    AsyncRedisRateLimitBackend,
)
from ea_agentgate.exceptions import RateLimitError, TransactionFailed
from ea_agentgate.middleware.base import Middleware, MiddlewareChain, MiddlewareContext
from ea_agentgate.middleware.rate_limiter import RateLimiter
from ea_agentgate.providers.openai_async import AsyncOpenAIProvider
from ea_agentgate.trace import Trace

# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture(name="agent_fixture")
def _agent_fixture() -> Agent:
    """Create a basic agent fixture for testing."""
    return Agent()


@pytest.fixture(name="trace_fixture")
def _trace_fixture() -> Trace:
    """Create a trace fixture for testing."""
    return Trace(tool="test_tool", inputs={"x": 1})


@pytest.fixture(name="context_fixture")
def _context_fixture(trace_fixture: Trace) -> MiddlewareContext:
    """Create a middleware context for testing."""
    return MiddlewareContext(
        tool="test_tool",
        inputs={"x": 1},
        trace=trace_fixture,
        agent_id="test-agent",
    )


# ============================================================================
# Test Async Agent Methods
# ============================================================================


class TestAgentAcall:
    """Tests for Agent.acall() method."""

    @pytest.mark.asyncio
    async def test_acall_sync_tool(self, agent_fixture: Agent) -> None:
        """Test acall with a synchronous tool function."""

        @agent_fixture.tool
        def add(a: int, b: int) -> int:
            return a + b

        result = await agent_fixture.acall("add", a=2, b=3)
        assert result == 5

    @pytest.mark.asyncio
    async def test_acall_async_tool(self, agent_fixture: Agent) -> None:
        """Test acall with an async tool function."""

        @agent_fixture.tool
        async def async_add(a: int, b: int) -> int:
            await asyncio.sleep(0.01)  # Simulate async work
            return a + b

        result = await agent_fixture.acall("async_add", a=2, b=3)
        assert result == 5

    @pytest.mark.asyncio
    async def test_acall_with_positional_args(self, agent_fixture: Agent) -> None:
        """Test acall with positional arguments."""

        @agent_fixture.tool
        def multiply(x: int, y: int) -> int:
            return x * y

        result = await agent_fixture.acall("multiply", 4, 5)
        assert result == 20

    @pytest.mark.asyncio
    async def test_acall_creates_trace(self, agent_fixture: Agent) -> None:
        """Test that acall creates a test_trace."""

        @agent_fixture.tool
        def simple() -> str:
            return "done"

        await agent_fixture.acall("simple")

        assert len(agent_fixture.traces) == 1
        assert agent_fixture.traces[0].tool == "simple"
        assert agent_fixture.traces[0].result.output == "done"

    @pytest.mark.asyncio
    async def test_acall_unknown_tool(self, agent_fixture: Agent) -> None:
        """Test acall raises for unknown tool."""
        with pytest.raises(KeyError, match="Tool 'unknown' not registered"):
            await agent_fixture.acall("unknown")

    @pytest.mark.asyncio
    async def test_acall_parallel_execution(self, agent_fixture: Agent) -> None:
        """Test multiple acall tasks run in parallel."""
        call_times: list[float] = []

        @agent_fixture.tool
        async def slow_tool(delay: float) -> float:
            start = time.time()
            await asyncio.sleep(delay)
            call_times.append(time.time() - start)
            return delay

        # Run 3 calls in parallel
        results = await asyncio.gather(
            agent_fixture.acall("slow_tool", delay=0.1),
            agent_fixture.acall("slow_tool", delay=0.1),
            agent_fixture.acall("slow_tool", delay=0.1),
        )

        assert results == [0.1, 0.1, 0.1]
        # All should complete around the same time (parallel execution)
        assert all(t < 0.2 for t in call_times)


class TestAgentAtransaction:
    """Tests for Agent.atransaction() method."""

    @pytest.mark.asyncio
    async def test_atransaction_success(self, agent_fixture: Agent) -> None:
        """Test successful async transaction."""
        results: list[str] = []

        @agent_fixture.tool
        async def step1() -> str:
            results.append("step1")
            return "s1"

        @agent_fixture.tool
        async def step2() -> str:
            results.append("step2")
            return "s2"

        async with agent_fixture.atransaction():
            await agent_fixture.acall("step1")
            await agent_fixture.acall("step2")

        assert results == ["step1", "step2"]
        assert len(agent_fixture.traces) == 2

    @pytest.mark.asyncio
    async def test_atransaction_rollback_on_failure(self, agent_fixture: Agent) -> None:
        """Test async transaction rollback on failure."""
        compensated: list[str] = []

        @agent_fixture.tool
        async def create_user(user_id: str) -> str:
            return user_id

        async def undo_create_user(output: str) -> None:
            compensated.append(output)

        @agent_fixture.tool
        async def failing_step() -> None:
            raise ValueError("Something went wrong")

        with pytest.raises(TransactionFailed):
            async with agent_fixture.atransaction():
                agent_fixture.compensate("create_user", undo_create_user)
                await agent_fixture.acall("create_user", user_id="user-123")
                await agent_fixture.acall("failing_step")

        # Compensation should have been called
        assert compensated == ["user-123"]

    @pytest.mark.asyncio
    async def test_atransaction_async_compensation(self, agent_fixture: Agent) -> None:
        """Test transaction with async compensation function."""
        compensated: list[str] = []

        @agent_fixture.tool
        async def create_resource(name: str) -> str:
            return name

        async def undo_create_resource(output: str) -> None:
            await asyncio.sleep(0.01)  # Async compensation
            compensated.append(f"undone:{output}")

        @agent_fixture.tool
        async def fail() -> None:
            raise RuntimeError("Boom")

        with pytest.raises(TransactionFailed):
            async with agent_fixture.atransaction():
                agent_fixture.compensate("create_resource", undo_create_resource)
                await agent_fixture.acall("create_resource", name="res1")
                await agent_fixture.acall("fail")

        assert compensated == ["undone:res1"]


class TestSyncCallWithAsyncTool:
    """Tests for calling async tools from sync context."""

    def test_sync_call_async_tool_no_loop(self) -> None:
        """Test sync call() with async tool when no event loop running."""
        agent_instance = Agent()

        @agent_instance.tool
        async def async_func() -> str:
            await asyncio.sleep(0.01)
            return "async result"

        # This should work - no event loop running
        result = agent_instance.call("async_func")
        assert result == "async result"

    def test_sync_call_async_tool_uses_fresh_agent(self) -> None:
        """Test sync call() works repeatedly with a fresh agent instance."""
        fresh_agent = Agent()

        @fresh_agent.tool
        async def ping() -> str:
            return "pong"

        assert fresh_agent.call("ping") == "pong"


# ============================================================================
# Test Async Middleware Chain
# ============================================================================


class TestMiddlewareChainAexecute:
    """Tests for MiddlewareChain.aexecute() method."""

    @pytest.mark.asyncio
    async def test_aexecute_sync_tool(self, context_fixture: MiddlewareContext) -> None:
        """Test aexecute with sync tool."""
        chain = MiddlewareChain([])

        def sync_tool(x: int) -> int:
            return x * 2

        result = await chain.aexecute(context_fixture, sync_tool)
        assert result == 2

    @pytest.mark.asyncio
    async def test_aexecute_async_tool(self, context_fixture: MiddlewareContext) -> None:
        """Test aexecute with async tool."""
        chain = MiddlewareChain([])

        async def async_tool(x: int) -> int:
            await asyncio.sleep(0.01)
            return x * 3

        result = await chain.aexecute(context_fixture, async_tool)
        assert result == 3

    @pytest.mark.asyncio
    async def test_aexecute_runs_abefore_hooks(self, context_fixture: MiddlewareContext) -> None:
        """Test that aexecute runs abefore hooks."""

        class TrackingMiddleware(Middleware):
            """Middleware that tracks whether before hooks are called."""

            def __init__(self) -> None:
                super().__init__()
                self.before_called = False
                self.abefore_called = False

            async def abefore(self, ctx: MiddlewareContext) -> None:
                self.abefore_called = True

        mw = TrackingMiddleware()
        chain = MiddlewareChain([mw])

        await chain.aexecute(context_fixture, lambda x: x)

        assert mw.abefore_called

    @pytest.mark.asyncio
    async def test_aexecute_runs_aafter_hooks(self, context_fixture: MiddlewareContext) -> None:
        """Test that aexecute runs aafter hooks in reverse order."""
        call_order: list[str] = []

        class OrderTracker(Middleware):
            """Middleware that tracks the order of hook calls."""

            def __init__(self, name: str) -> None:
                super().__init__()
                self._name = name

            async def abefore(self, _ctx: MiddlewareContext) -> None:
                call_order.append(f"before:{self._name}")

            async def aafter(
                self, _ctx: MiddlewareContext, result: Any, error: Exception | None
            ) -> None:
                call_order.append(f"after:{self._name}")

        chain = MiddlewareChain([OrderTracker("A"), OrderTracker("B")])
        await chain.aexecute(context_fixture, lambda x: x)

        assert call_order == ["before:A", "before:B", "after:B", "after:A"]

    @pytest.mark.asyncio
    async def test_aexecute_cache_hit(self, context_fixture: MiddlewareContext) -> None:
        """Test aexecute respects cache hit."""
        context_fixture.metadata["cache_hit"] = True
        context_fixture.metadata["cached_result"] = "cached_value"

        chain = MiddlewareChain([])
        tool_called = False

        def tool(_x: int) -> str:
            nonlocal tool_called
            tool_called = True
            return "fresh_value"

        result = await chain.aexecute(context_fixture, tool)

        assert result == "cached_value"
        assert not tool_called


# ============================================================================
# Test Middleware Default Async Behavior
# ============================================================================


class TestMiddlewareDefaultAsync:
    """Tests for default async behavior in Middleware base class."""

    @pytest.mark.asyncio
    async def test_default_abefore_calls_before(self, context_fixture: MiddlewareContext) -> None:
        """Test default abefore calls sync before in thread pool."""

        class SyncMiddleware(Middleware):
            """Middleware with sync before hook for testing."""

            def __init__(self) -> None:
                super().__init__()
                self.before_called = False

            def before(self, ctx: MiddlewareContext) -> None:
                self.before_called = True

        mw = SyncMiddleware()
        await mw.abefore(context_fixture)

        assert mw.before_called

    @pytest.mark.asyncio
    async def test_default_aafter_calls_after(self, context_fixture: MiddlewareContext) -> None:
        """Test default aafter calls sync after in thread pool."""

        class SyncMiddleware(Middleware):
            """Middleware with sync after hook for testing."""

            def __init__(self) -> None:
                super().__init__()
                self.after_called = False
                self.received_result: Any = None

            def after(self, ctx: MiddlewareContext, result: Any, error: Exception | None) -> None:
                self.after_called = True
                self.received_result = result

        mw = SyncMiddleware()
        await mw.aafter(context_fixture, "test_result", None)

        assert mw.after_called
        assert mw.received_result == "test_result"

    def test_is_async_native_default(self) -> None:
        """Test is_async_native returns False by default."""

        class BasicMiddleware(Middleware):
            """Basic middleware for testing default behavior."""

        mw = BasicMiddleware()
        assert mw.is_async_native() is False


# ============================================================================
# Test Async Rate Limiter
# ============================================================================


class TestAsyncRateLimiter:
    """Tests for async rate limiter middleware."""

    @pytest.mark.asyncio
    async def test_rate_limiter_sync_fallback(self, context_fixture: MiddlewareContext) -> None:
        """Test rate limiter falls back to sync when no async backend."""

        limiter = RateLimiter(max_calls=10, window="1s")
        assert limiter.is_async_native() is False

        # Should work via thread pool fallback
        await limiter.abefore(context_fixture)

    @pytest.mark.asyncio
    async def test_rate_limiter_async_backend(self, context_fixture: MiddlewareContext) -> None:
        """Test rate limiter with async backend."""

        # Mock async backend
        mock_backend = AsyncMock()
        mock_backend.arecord_call = AsyncMock(return_value=1)

        limiter = RateLimiter(max_calls=10, window="1s", async_backend=mock_backend)
        assert limiter.is_async_native() is True

        await limiter.abefore(context_fixture)

        mock_backend.arecord_call.assert_called_once()

    @pytest.mark.asyncio
    async def test_rate_limiter_async_exceeds_limit(
        self, context_fixture: MiddlewareContext
    ) -> None:
        """Test async rate limiter raises when limit exceeded."""

        mock_backend = AsyncMock()
        mock_backend.arecord_call = AsyncMock(return_value=11)  # Over limit

        limiter = RateLimiter(max_calls=10, window="1s", async_backend=mock_backend)

        with pytest.raises(RateLimitError):
            await limiter.abefore(context_fixture)


# ============================================================================
# Test Async Redis Backends (Mock Tests)
# ============================================================================


class TestAsyncRedisRateLimitBackend:
    """Tests for async Redis rate limit backend."""

    @pytest.mark.asyncio
    async def test_arecord_call_returns_count(self) -> None:
        """Test arecord_call returns count."""
        mock_redis = AsyncMock()
        mock_pipeline = MagicMock()
        mock_pipeline.__aenter__ = AsyncMock(return_value=mock_pipeline)
        mock_pipeline.__aexit__ = AsyncMock(return_value=None)
        mock_pipeline.execute = AsyncMock(return_value=[0, True, 5, True])
        mock_pipeline.zremrangebyscore = MagicMock()
        mock_pipeline.zadd = MagicMock()
        mock_pipeline.zcard = MagicMock()
        mock_pipeline.expire = MagicMock()
        mock_redis.pipeline = MagicMock(return_value=mock_pipeline)
        mock_redis.register_script = MagicMock(return_value=AsyncMock(return_value=0))

        backend = AsyncRedisRateLimitBackend(mock_redis)
        count = await backend.arecord_call("test-key", 1000.0, 60.0)

        assert count == 5

    @pytest.mark.asyncio
    async def test_arate_limit_uses_registered_script(self) -> None:
        """Test arate_limit delegates to the registered Lua script."""
        rate_limit_script = AsyncMock(return_value=1)
        mock_redis = AsyncMock()
        mock_redis.register_script = MagicMock(return_value=rate_limit_script)

        backend = AsyncRedisRateLimitBackend(mock_redis, key_prefix="test:ratelimit:")
        count = await backend.arate_limit("agent:test", max_calls=5, window_seconds=60)

        assert count == 1
        rate_limit_script.assert_awaited_once()


class TestAsyncRedisCacheBackend:
    """Tests for async Redis cache backend."""

    @pytest.mark.asyncio
    async def test_aget_returns_value(self) -> None:
        """Test aget returns cached value."""

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=json.dumps({"result": "cached"}))

        backend = AsyncRedisCacheBackend(mock_redis)
        value = await backend.aget("test-key")

        assert value == {"result": "cached"}

    @pytest.mark.asyncio
    async def test_aget_returns_none_for_missing(self) -> None:
        """Test aget returns None for missing key."""

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)

        backend = AsyncRedisCacheBackend(mock_redis)
        value = await backend.aget("missing-key")

        assert value is None


class TestAsyncRedisPIIVaultBackend:
    """Tests for async Redis PII vault backend."""

    @pytest.mark.asyncio
    async def test_astore_writes_entry(self) -> None:
        """Test astore writes entry and index via pipeline."""

        mock_redis = AsyncMock()
        mock_pipeline = MagicMock()
        mock_pipeline.__aenter__ = AsyncMock(return_value=mock_pipeline)
        mock_pipeline.__aexit__ = AsyncMock(return_value=None)
        mock_pipeline.execute = AsyncMock()
        mock_pipeline.set = MagicMock()
        mock_pipeline.setex = MagicMock()
        mock_pipeline.sadd = MagicMock()
        mock_pipeline.expire = MagicMock()
        mock_redis.pipeline = MagicMock(return_value=mock_pipeline)

        backend = AsyncRedisPIIVaultBackend(mock_redis)
        await backend.astore("<PERSON_1>", "Alice", "PERSON", session_id="sess_1")

        mock_pipeline.set.assert_called_once()
        mock_pipeline.sadd.assert_called_once()
        mock_pipeline.setex.assert_not_called()
        mock_pipeline.expire.assert_not_called()
        mock_pipeline.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_aretrieve_returns_original(self) -> None:
        """Test aretrieve returns original value from stored entry."""

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(
            return_value=json.dumps({"original": "Alice", "pii_type": "PERSON"})
        )

        backend = AsyncRedisPIIVaultBackend(mock_redis)
        original = await backend.aretrieve("<PERSON_1>", session_id="sess_1")

        assert original == "Alice"

    @pytest.mark.asyncio
    async def test_asearch_similar_uses_mget(self) -> None:
        """Test asearch_similar uses MGET for batching."""

        mock_redis = AsyncMock()
        mock_redis.smembers = AsyncMock(return_value={b"key1", b"key2"})

        # Return embeddings that match
        emb1 = json.dumps({"embedding": [1.0, 0.0, 0.0], "created_at": 1000})
        emb2 = json.dumps({"embedding": [0.9, 0.1, 0.0], "created_at": 1001})
        mock_redis.mget = AsyncMock(
            side_effect=[
                [emb1.encode(), emb2.encode()],  # First MGET for embeddings
                [json.dumps({"result": "v1"}).encode()],  # Second MGET for values
            ]
        )
        mock_redis.srem = AsyncMock()

        backend = AsyncRedisCacheBackend(mock_redis)
        results = await backend.asearch_similar([1.0, 0.0, 0.0], threshold=0.8, limit=1)

        # Should have called MGET (batch operation)
        assert mock_redis.mget.call_count >= 1
        assert len(results) == 1


# ============================================================================
# Test Async Providers (Mock Tests)
# ============================================================================


class TestAsyncOpenAIProvider:
    """Tests for async OpenAI provider."""

    @pytest.fixture(autouse=True)
    def mock_openai(self):
        """Mock openai module for all tests in this class."""
        # Create comprehensive mock of openai module hierarchy
        mock_openai_module = MagicMock()
        mock_openai_module.AsyncOpenAI = MagicMock()
        mock_openai_module.OpenAI = MagicMock()

        # Mock openai.types submodules
        mock_types = MagicMock()
        mock_chat = MagicMock()
        mock_chat_completion = MagicMock()
        mock_chat.chat_completion = mock_chat_completion

        mock_types.chat = mock_chat
        mock_openai_module.types = mock_types

        # Register all mocked modules
        sys.modules["openai"] = mock_openai_module
        sys.modules["openai.types"] = mock_types
        sys.modules["openai.types.chat"] = mock_chat
        sys.modules["openai.types.chat.chat_completion"] = mock_chat_completion

        # Clear cached provider modules
        for mod in list(sys.modules.keys()):
            if "openai_async" in mod or "openai_common" in mod:
                del sys.modules[mod]

        yield

        # Cleanup
        for mod in [
            "openai",
            "openai.types",
            "openai.types.chat",
            "openai.types.chat.chat_completion",
        ]:
            sys.modules.pop(mod, None)
        for mod in list(sys.modules.keys()):
            if "openai_async" in mod or "openai_common" in mod:
                sys.modules.pop(mod, None)

    @pytest.mark.asyncio
    async def test_acomplete_returns_response(self) -> None:
        """Test acomplete returns LLM response."""

        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.choices = [
            MagicMock(message=MagicMock(content="Hello!"), finish_reason="stop")
        ]
        mock_response.model = "gpt-4o-mini"
        mock_response.usage = MagicMock(prompt_tokens=10, completion_tokens=5, total_tokens=15)
        mock_response.id = "chatcmpl-123"

        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

        provider = AsyncOpenAIProvider(client=mock_client)
        response = await provider.acomplete("Hi")

        assert response.content == "Hello!"
        assert response.model == "gpt-4o-mini"

    @pytest.mark.asyncio
    async def test_aembed_returns_vector(self) -> None:
        """Test aembed returns embedding vector."""

        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.data = [MagicMock(embedding=[0.1, 0.2, 0.3])]

        mock_client.embeddings.create = AsyncMock(return_value=mock_response)

        provider = AsyncOpenAIProvider(client=mock_client)
        embedding = await provider.aembed("Hello world")

        assert embedding == [0.1, 0.2, 0.3]


# ============================================================================
# Integration Tests
# ============================================================================


class TestAsyncIntegration:
    """Integration tests for async functionality."""

    @pytest.mark.asyncio
    async def test_full_async_pipeline(self) -> None:
        """Test complete async pipeline with middleware."""

        class CountingMiddleware(Middleware):
            """Middleware that counts hook invocations."""

            def __init__(self) -> None:
                super().__init__()
                self.count = 0

            async def abefore(self, _ctx: MiddlewareContext) -> None:
                self.count += 1

        mw = CountingMiddleware()
        counting_agent = Agent(middleware=[mw])

        @counting_agent.tool
        async def async_tool(x: int) -> int:
            return x * 2

        # Run multiple async calls
        results = await asyncio.gather(
            counting_agent.acall("async_tool", x=1),
            counting_agent.acall("async_tool", x=2),
            counting_agent.acall("async_tool", x=3),
        )

        assert results == [2, 4, 6]
        assert mw.count == 3

    @pytest.mark.asyncio
    async def test_async_error_handling(self) -> None:
        """Test async error handling through middleware."""

        class ErrorLoggingMiddleware(Middleware):
            """Middleware that logs errors for testing."""

            def __init__(self) -> None:
                super().__init__()
                self.errors: list[str] = []

            async def aafter(
                self, _ctx: MiddlewareContext, result: Any, error: Exception | None
            ) -> None:
                if error:
                    self.errors.append(str(error))

        mw = ErrorLoggingMiddleware()
        error_agent = Agent(middleware=[mw])

        @error_agent.tool
        async def failing_tool() -> None:
            raise ValueError("Test error")

        with pytest.raises(ValueError):
            await error_agent.acall("failing_tool")

        assert "Test error" in mw.errors[0]
