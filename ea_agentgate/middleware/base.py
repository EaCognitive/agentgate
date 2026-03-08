"""Base middleware class."""

from __future__ import annotations

import asyncio
import inspect
from abc import ABC
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TYPE_CHECKING
from collections.abc import Callable

if TYPE_CHECKING:
    from ..trace import Trace


class FailureMode(Enum):
    """Defines middleware behavior when errors occur.

    - FAIL_OPEN: Pass through requests on error (graceful degradation)
    - FAIL_CLOSED: Block requests on error (secure by default)
    - RETRY: Attempt retries before failing
    """

    FAIL_OPEN = "fail_open"
    FAIL_CLOSED = "fail_closed"
    RETRY = "retry"


@dataclass
class MiddlewareContext:
    """
    Context passed through middleware chain.

    Contains all information about the current tool call
    and allows middleware to communicate with each other.
    """

    tool: str
    inputs: dict[str, Any]
    trace: "Trace"
    agent_id: str | None = None
    session_id: str | None = None
    user_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    # Set by middleware
    cost: float = 0.0
    approved_by: str | None = None
    approval_id: str | None = None


class Middleware(ABC):
    """
    Base class for middleware.

    Middleware runs before and/or after tool execution.
    Implement `before()` to validate/modify before execution.
    Implement `after()` to log/process after execution.

    Example:
        class LoggingMiddleware(Middleware):
            def before(self, ctx: MiddlewareContext) -> None:
                print(f"Calling {ctx.tool} with {ctx.inputs}")

            def after(self, ctx: MiddlewareContext, result: Any, error: Exception | None) -> None:
                if error:
                    print(f"{ctx.tool} failed: {error}")
                else:
                    print(f"{ctx.tool} returned: {result}")

    Attributes:
        failure_mode: How middleware handles errors (default: FAIL_CLOSED)
        timeout_ms: Operation timeout in milliseconds (None = no timeout)
        max_retries: Maximum retry attempts for RETRY mode (default: 3)
    """

    def __init__(
        self,
        *,
        failure_mode: FailureMode = FailureMode.FAIL_CLOSED,
        timeout_ms: int | None = None,
        max_retries: int = 3,
    ):
        self.failure_mode = failure_mode
        self.timeout_ms = timeout_ms
        self.max_retries = max_retries if max_retries > 0 else 3

    @property
    def name(self) -> str:
        """Return middleware name."""
        return self.__class__.__name__

    def before(self, ctx: MiddlewareContext) -> None:
        """
        Run before tool execution.

        Raise an exception to block execution.
        Modify ctx.inputs to transform parameters.
        """

    def after(self, ctx: MiddlewareContext, result: Any, error: Exception | None) -> None:
        """
        Run after tool execution (success or failure).

        Args:
            ctx: The middleware context
            result: The tool's return value (None if error)
            error: The exception if tool failed (None if success)
        """

    # -------------------------------------------------------------------------
    # Async Methods
    # -------------------------------------------------------------------------

    async def abefore(self, ctx: MiddlewareContext) -> None:
        """
        Async before hook. Default runs sync `before()` in thread pool.

        Override this method for truly async operations (HTTP calls, Redis, LLM).
        The default implementation uses asyncio.to_thread() to avoid blocking
        the event loop with sync I/O operations.
        """
        await asyncio.to_thread(self.before, ctx)

    async def aafter(self, ctx: MiddlewareContext, result: Any, error: Exception | None) -> None:
        """
        Async after hook. Default runs sync `after()` in thread pool.

        Override this method for truly async operations.
        """
        await asyncio.to_thread(self.after, ctx, result, error)

    def is_async_native(self) -> bool:
        """
        Return True if this middleware has native async implementations.

        Used by MiddlewareChain to optimize execution - middleware with
        native async can skip the thread pool overhead.

        Override this to return True when you implement custom abefore/aafter.
        """
        return False


class MiddlewareChain:
    """Executes a chain of middleware around a tool call."""

    def __init__(self, middlewares: list[Middleware]):
        self.middlewares = middlewares

    def execute(
        self,
        ctx: MiddlewareContext,
        tool_fn: Callable[..., Any],
    ) -> Any:
        """
        Execute middleware chain around tool function.

        1. Run all `before()` hooks
        2. Check for cache hit (middleware can set ctx.metadata["cache_hit"])
        3. Execute tool (or return cached result)
        4. Run all `after()` hooks (in reverse order)

        Cache Support:
            Middleware can set ctx.metadata["cache_hit"] = True and
            ctx.metadata["cached_result"] to skip tool execution and
            return the cached result directly.
        """
        # Run before hooks
        for mw in self.middlewares:
            mw.before(ctx)

        # Check for cache hit (allows SemanticCache to short-circuit execution)
        result = None
        error = None

        if ctx.metadata.get("cache_hit") and "cached_result" in ctx.metadata:
            # Cache hit - use cached result instead of executing tool
            result = ctx.metadata["cached_result"]
        else:
            # Execute tool normally
            try:
                result = tool_fn(**ctx.inputs)
            except (OSError, RuntimeError, ValueError, KeyError, AttributeError, TypeError) as e:
                error = e

        # Run after hooks (reverse order)
        for mw in reversed(self.middlewares):
            mw.after(ctx, result, error)

        # Re-raise if there was an error
        if error:
            raise error

        if "result_override" in ctx.metadata:
            return ctx.metadata["result_override"]

        return result

    async def aexecute(
        self,
        ctx: MiddlewareContext,
        tool_fn: Callable[..., Any],
    ) -> Any:
        """
        Async execute middleware chain around tool function.

        1. Run all `abefore()` hooks
        2. Check for cache hit (middleware can set ctx.metadata["cache_hit"])
        3. Execute tool (await if coroutine, run in thread if sync)
        4. Run all `aafter()` hooks (in reverse order)

        Supports both sync and async tool functions. Sync tools are
        executed in a thread pool to avoid blocking the event loop.
        """
        # Run before hooks
        for mw in self.middlewares:
            await mw.abefore(ctx)

        # Check for cache hit (allows SemanticCache to short-circuit execution)
        result = None
        error = None

        if ctx.metadata.get("cache_hit") and "cached_result" in ctx.metadata:
            # Cache hit - use cached result instead of executing tool
            result = ctx.metadata["cached_result"]
        else:
            # Execute tool
            try:
                if inspect.iscoroutinefunction(tool_fn):
                    # Async tool - await directly
                    result = await tool_fn(**ctx.inputs)
                else:
                    # Sync tool - run in thread pool to not block event loop
                    result = await asyncio.to_thread(tool_fn, **ctx.inputs)
            except (OSError, RuntimeError, ValueError, KeyError, AttributeError, TypeError) as e:
                error = e

        # Run after hooks (reverse order)
        for mw in reversed(self.middlewares):
            await mw.aafter(ctx, result, error)

        # Re-raise if there was an error
        if error:
            raise error

        if "result_override" in ctx.metadata:
            return ctx.metadata["result_override"]

        return result
