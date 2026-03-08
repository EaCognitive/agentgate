"""Rate limiting middleware."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Literal, TYPE_CHECKING

from .base import Middleware, MiddlewareContext
from ..exceptions import RateLimitError
from ..backends.memory import MemoryRateLimitBackend

if TYPE_CHECKING:
    from ..backends import RateLimitBackend, AsyncRateLimitBackend


def _get_memory_backend():
    """Get memory backend instance."""
    return MemoryRateLimitBackend()


@dataclass
class RateLimitConfig:
    """Configuration for a rate limit."""

    max_calls: int
    window_seconds: float
    scope: Literal["global", "tool", "user", "session"] = "global"


class RateLimiter(Middleware):
    """
    Rate limits tool calls.

    Prevents runaway agents from making too many calls.

    Example:
        limiter = RateLimiter(
            max_calls=100,
            window="1m",
            scope="session",
        )

        # Or multiple limits:
        limiter = RateLimiter(limits=[
            RateLimitConfig(max_calls=10, window_seconds=1, scope="global"),
            RateLimitConfig(max_calls=100, window_seconds=60, scope="session"),
        ])
    """

    def __init__(
        self,
        *,
        max_calls: int | None = None,
        window: str | float | None = None,
        scope: Literal["global", "tool", "user", "session"] = "global",
        limits: list[RateLimitConfig] | None = None,
        backend: "RateLimitBackend | None" = None,
        async_backend: "AsyncRateLimitBackend | None" = None,
    ):
        """
        Initialize rate limiter.

        Args:
            max_calls: Maximum calls allowed in window
            window: Time window (e.g., "1m", "30s", "1h" or seconds as float)
            scope: What to rate limit by
            limits: Multiple rate limit configs
            backend: Optional backend for distributed rate limiting (default: in-memory)
            async_backend: Optional async backend for distributed rate limiting
        """
        super().__init__()
        self.limits: list[RateLimitConfig] = []

        if limits:
            self.limits = limits
        elif max_calls is not None and window is not None:
            window_seconds = self._parse_window(window)
            self.limits.append(RateLimitConfig(max_calls, window_seconds, scope))

        # Use provided backend or default to in-memory
        if backend is not None:
            self._backend = backend
        else:
            self._backend = _get_memory_backend()

        # Async backend (optional)
        self._async_backend: "AsyncRateLimitBackend | None" = async_backend

    def _parse_window(self, window: str | float) -> float:
        """Parse window string to seconds."""
        if isinstance(window, (int, float)):
            return float(window)

        window = window.strip().lower()
        if window.endswith("s"):
            return float(window[:-1])
        if window.endswith("m"):
            return float(window[:-1]) * 60
        if window.endswith("h"):
            return float(window[:-1]) * 3600
        if window.endswith("d"):
            return float(window[:-1]) * 86400
        return float(window)

    def _get_scope_key(self, config: RateLimitConfig, ctx: MiddlewareContext) -> str:
        """Get the key for tracking calls based on scope."""
        if config.scope == "global":
            return "global"
        if config.scope == "tool":
            return f"tool:{ctx.tool}"
        if config.scope == "user":
            return f"user:{ctx.user_id or 'anonymous'}"
        if config.scope == "session":
            return f"session:{ctx.session_id or 'default'}"
        return "global"

    def before(self, ctx: MiddlewareContext) -> None:
        """Check rate limits before execution."""
        now = time.time()

        for config in self.limits:
            key = self._get_scope_key(config, ctx)

            # Record call and get current count (backend handles window cleanup)
            count = self._backend.record_call(key, now, config.window_seconds)

            # Check limit
            if count > config.max_calls:
                retry_after = config.window_seconds
                msg = (
                    f"Rate limit exceeded: {config.max_calls} calls "
                    f"per {config.window_seconds}s ({config.scope})"
                )
                ctx.trace.block(msg, self.name)
                raise RateLimitError(
                    msg,
                    retry_after=retry_after,
                    middleware=self.name,
                    tool=ctx.tool,
                    trace_id=ctx.trace.id,
                    context={
                        "current_calls": count,
                        "max_calls": config.max_calls,
                        "window_seconds": config.window_seconds,
                        "scope": config.scope,
                    },
                )

    def reset(self, scope_key: str | None = None) -> None:
        """Reset rate limit counters."""
        self._backend.reset(scope_key)

    # -------------------------------------------------------------------------
    # Async Methods
    # -------------------------------------------------------------------------

    def is_async_native(self) -> bool:
        """Return True if async backend is configured."""
        return self._async_backend is not None

    async def abefore(self, ctx: MiddlewareContext) -> None:
        """Async check rate limits before execution."""
        if self._async_backend is None:
            # Fall back to sync via thread pool
            await asyncio.to_thread(self.before, ctx)
            return

        now = time.time()

        for config in self.limits:
            key = self._get_scope_key(config, ctx)

            # Record call and get current count (backend handles window cleanup)
            count = await self._async_backend.arecord_call(key, now, config.window_seconds)

            # Check limit
            if count > config.max_calls:
                retry_after = config.window_seconds
                msg = (
                    f"Rate limit exceeded: {config.max_calls} calls "
                    f"per {config.window_seconds}s ({config.scope})"
                )
                ctx.trace.block(msg, self.name)
                raise RateLimitError(
                    msg,
                    retry_after=retry_after,
                    middleware=self.name,
                    tool=ctx.tool,
                    trace_id=ctx.trace.id,
                    context={
                        "current_calls": count,
                        "max_calls": config.max_calls,
                        "window_seconds": config.window_seconds,
                        "scope": config.scope,
                    },
                )

    async def areset(self, scope_key: str | None = None) -> None:
        """Async reset rate limit counters."""
        if self._async_backend is not None:
            await self._async_backend.areset(scope_key)
        else:
            await asyncio.to_thread(self._backend.reset, scope_key)
