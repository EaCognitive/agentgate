"""Circuit breaker implementation for resilient middleware.

Implements the Circuit Breaker pattern to prevent cascade failures by
detecting repeated failures and temporarily stopping requests to failing services.
"""

from __future__ import annotations

import inspect
import logging
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, TypeVar, cast
from collections.abc import Callable

logger = logging.getLogger(__name__)

T = TypeVar("T")


class CircuitState(Enum):
    """Circuit breaker states.

    - CLOSED: Normal operation, requests pass through
    - OPEN: Failure threshold exceeded, requests fail fast
    - HALF_OPEN: Testing recovery, limited requests allowed
    """

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerError(Exception):
    """Raised when circuit breaker is open."""

    def __init__(self, message: str, state: CircuitState):
        self.state = state
        super().__init__(message)


@dataclass
class CircuitBreakerStats:
    """Statistics for circuit breaker monitoring."""

    failure_count: int = 0
    success_count: int = 0
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    last_failure_time: float | None = None
    last_success_time: float | None = None
    state_transitions: int = 0
    total_calls: int = 0
    total_failures: int = 0
    total_successes: int = 0


class CircuitBreaker:
    """Circuit breaker for preventing cascade failures.

    The circuit breaker tracks failures and automatically opens (fails fast)
    when failure threshold is exceeded. After a timeout period, it enters
    half-open state to test recovery.

    Example:
        breaker = CircuitBreaker(
            failure_threshold=5,
            recovery_timeout=60.0,
            half_open_max_calls=3,
        )

        result = breaker.call(risky_operation, arg1, arg2)

    Args:
        failure_threshold: Number of consecutive failures to open circuit
        recovery_timeout: Seconds to wait before attempting recovery
        half_open_max_calls: Number of test calls in half-open state
        fallback_fn: Optional fallback function when circuit is open
    """

    def __init__(
        self,
        *,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        half_open_max_calls: int = 3,
        fallback_fn: Callable[..., Any] | None = None,
    ):
        if failure_threshold < 1:
            raise ValueError(f"failure_threshold must be >= 1, got {failure_threshold}")
        if recovery_timeout <= 0:
            raise ValueError(f"recovery_timeout must be > 0, got {recovery_timeout}")
        if half_open_max_calls < 1:
            raise ValueError(f"half_open_max_calls must be >= 1, got {half_open_max_calls}")

        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls
        self.fallback_fn = fallback_fn

        self._state = CircuitState.CLOSED
        self._stats = CircuitBreakerStats()
        self._opened_at: float | None = None
        self._half_open_calls = 0
        self._lock = threading.RLock()

    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        with self._lock:
            return self._state

    @property
    def stats(self) -> CircuitBreakerStats:
        """Get circuit breaker statistics."""
        with self._lock:
            return CircuitBreakerStats(
                failure_count=self._stats.failure_count,
                success_count=self._stats.success_count,
                consecutive_failures=self._stats.consecutive_failures,
                consecutive_successes=self._stats.consecutive_successes,
                last_failure_time=self._stats.last_failure_time,
                last_success_time=self._stats.last_success_time,
                state_transitions=self._stats.state_transitions,
                total_calls=self._stats.total_calls,
                total_failures=self._stats.total_failures,
                total_successes=self._stats.total_successes,
            )

    def call(self, func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        """Execute function with circuit breaker protection.

        Args:
            func: Function to execute
            *args: Positional arguments for function
            **kwargs: Keyword arguments for function

        Returns:
            Function result if circuit allows execution

        Raises:
            CircuitBreakerError: If circuit is open
            Exception: Original exception from function
        """
        with self._lock:
            self._stats.total_calls += 1
            self._check_and_update_state()

            if self._state == CircuitState.OPEN:
                if self.fallback_fn is not None:
                    logger.warning("Circuit open, using fallback function")
                    return cast(T, self.fallback_fn(*args, **kwargs))
                raise CircuitBreakerError(f"Circuit breaker is {self._state.value}", self._state)

            if self._state == CircuitState.HALF_OPEN:
                if self._half_open_calls >= self.half_open_max_calls:
                    raise CircuitBreakerError("Half-open call limit exceeded", self._state)
                self._half_open_calls += 1

        try:
            result = func(*args, **kwargs)
            self._record_success()
            return result
        except Exception:
            self._record_failure()
            raise

    async def acall(
        self,
        func: Callable[..., T | Any],
        *args: Any,
        **kwargs: Any,
    ) -> T:
        """Async version of call().

        Args:
            func: Async function to execute
            *args: Positional arguments for function
            **kwargs: Keyword arguments for function

        Returns:
            Function result if circuit allows execution

        Raises:
            CircuitBreakerError: If circuit is open
            Exception: Original exception from function
        """
        with self._lock:
            self._stats.total_calls += 1
            self._check_and_update_state()

            if self._state == CircuitState.OPEN:
                if self.fallback_fn is not None:
                    logger.warning("Circuit open, using fallback function")
                    fallback_result = self.fallback_fn(*args, **kwargs)
                    if inspect.isawaitable(fallback_result):
                        awaited_fallback = await fallback_result
                        return cast(T, awaited_fallback)
                    return cast(T, fallback_result)
                raise CircuitBreakerError(f"Circuit breaker is {self._state.value}", self._state)

            if self._state == CircuitState.HALF_OPEN:
                if self._half_open_calls >= self.half_open_max_calls:
                    raise CircuitBreakerError("Half-open call limit exceeded", self._state)
                self._half_open_calls += 1

        try:
            result = func(*args, **kwargs)
            if inspect.isawaitable(result):
                awaited_result = await result
                result_value = awaited_result
            else:
                result_value = result
            self._record_success()
            return cast(T, result_value)
        except Exception:
            self._record_failure()
            raise

    def _check_and_update_state(self) -> None:
        """Check if state transition is needed based on time and stats."""
        now = time.time()

        if self._state == CircuitState.OPEN:
            if self._opened_at is not None and now - self._opened_at >= self.recovery_timeout:
                self._transition_to(CircuitState.HALF_OPEN)
                self._half_open_calls = 0
                logger.info("Circuit breaker entering half-open state for recovery test")

    def _record_success(self) -> None:
        """Record successful call and update state."""
        with self._lock:
            now = time.time()
            self._stats.success_count += 1
            self._stats.total_successes += 1
            self._stats.consecutive_successes += 1
            self._stats.consecutive_failures = 0
            self._stats.last_success_time = now

            if self._state == CircuitState.HALF_OPEN:
                if self._stats.consecutive_successes >= self.half_open_max_calls:
                    self._transition_to(CircuitState.CLOSED)
                    self._stats.consecutive_failures = 0
                    logger.info("Circuit breaker recovered, closing circuit")

    def _record_failure(self) -> None:
        """Record failed call and update state."""
        with self._lock:
            now = time.time()
            self._stats.failure_count += 1
            self._stats.total_failures += 1
            self._stats.consecutive_failures += 1
            self._stats.consecutive_successes = 0
            self._stats.last_failure_time = now

            if self._state == CircuitState.HALF_OPEN:
                self._transition_to(CircuitState.OPEN)
                self._opened_at = now
                logger.warning("Circuit breaker recovery failed, reopening circuit")
            elif self._state == CircuitState.CLOSED:
                if self._stats.consecutive_failures >= self.failure_threshold:
                    self._transition_to(CircuitState.OPEN)
                    self._opened_at = now
                    logger.warning(
                        "Circuit breaker opened due to %d consecutive failures",
                        self._stats.consecutive_failures,
                    )

    def _transition_to(self, new_state: CircuitState) -> None:
        """Transition to new state."""
        if new_state != self._state:
            old_state = self._state
            self._state = new_state
            self._stats.state_transitions += 1
            logger.info("Circuit breaker state: %s -> %s", old_state.value, new_state.value)

    def reset(self) -> None:
        """Reset circuit breaker to initial state."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._stats = CircuitBreakerStats()
            self._opened_at = None
            self._half_open_calls = 0
            logger.info("Circuit breaker reset")


__all__ = [
    "CircuitBreaker",
    "CircuitBreakerError",
    "CircuitState",
]
