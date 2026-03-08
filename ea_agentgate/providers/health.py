"""
Provider Health Tracking for monitoring LLM provider availability.

Implements circuit breaker pattern and health metrics for
intelligent provider selection and automatic failover.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from threading import Lock
from typing import ClassVar


class CircuitState(str, Enum):
    """Circuit breaker states."""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing, requests blocked
    HALF_OPEN = "half_open"  # Testing recovery


@dataclass
class _CircuitBreakerMetrics:
    """Circuit breaker related metrics."""

    state: CircuitState = CircuitState.CLOSED
    consecutive_failures: int = 0
    circuit_opened_at: datetime | None = None


@dataclass
class _RequestMetrics:
    """Request-related metrics."""

    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    success_rate: float = 1.0


@dataclass
class _LatencyMetrics:
    """Latency-related metrics."""

    avg_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0


@dataclass
class _ErrorMetrics:
    """Error tracking metrics."""

    last_success: datetime | None = None
    last_failure: datetime | None = None
    last_error: str | None = None


@dataclass
class HealthMetrics:
    """Health metrics for a provider."""

    name: str
    circuit_breaker: _CircuitBreakerMetrics = field(default_factory=_CircuitBreakerMetrics)
    requests: _RequestMetrics = field(default_factory=_RequestMetrics)
    latency: _LatencyMetrics = field(default_factory=_LatencyMetrics)
    errors: _ErrorMetrics = field(default_factory=_ErrorMetrics)

    @property
    def is_healthy(self) -> bool:
        """Check if provider is considered healthy."""
        return self.circuit_breaker.state != CircuitState.OPEN

    @property
    def state(self) -> CircuitState:
        """Get circuit breaker state."""
        return self.circuit_breaker.state

    @property
    def total_requests(self) -> int:
        """Get total requests."""
        return self.requests.total_requests

    @property
    def successful_requests(self) -> int:
        """Get successful requests."""
        return self.requests.successful_requests

    @property
    def failed_requests(self) -> int:
        """Get failed requests."""
        return self.requests.failed_requests

    @property
    def last_success(self) -> datetime | None:
        """Get last success time."""
        return self.errors.last_success

    @property
    def last_failure(self) -> datetime | None:
        """Get last failure time."""
        return self.errors.last_failure

    @property
    def last_error(self) -> str | None:
        """Get last error message."""
        return self.errors.last_error

    @property
    def avg_latency_ms(self) -> float:
        """Get average latency."""
        return self.latency.avg_latency_ms

    @property
    def p95_latency_ms(self) -> float:
        """Get p95 latency."""
        return self.latency.p95_latency_ms

    @property
    def p99_latency_ms(self) -> float:
        """Get p99 latency."""
        return self.latency.p99_latency_ms

    @property
    def success_rate(self) -> float:
        """Get success rate."""
        return self.requests.success_rate

    @property
    def consecutive_failures(self) -> int:
        """Get consecutive failures."""
        return self.circuit_breaker.consecutive_failures

    @property
    def circuit_opened_at(self) -> datetime | None:
        """Get when circuit opened."""
        return self.circuit_breaker.circuit_opened_at


@dataclass
class _CircuitBreakerStats:
    """Circuit breaker state tracking."""

    state: CircuitState = CircuitState.CLOSED
    opened_at: datetime | None = None
    half_open_attempts: int = 0


@dataclass
class _RequestStats:
    """Request counting and tracking."""

    successes: int = 0
    failures: int = 0
    consecutive_failures: int = 0


@dataclass
class _ErrorTracking:
    """Error history tracking."""

    last_success: datetime | None = None
    last_failure: datetime | None = None
    last_error: str | None = None


@dataclass
class _ProviderStats:
    """Internal statistics tracking for a provider."""

    latencies: deque[float] = field(default_factory=lambda: deque(maxlen=100))
    circuit: _CircuitBreakerStats = field(default_factory=_CircuitBreakerStats)
    requests: _RequestStats = field(default_factory=_RequestStats)
    errors: _ErrorTracking = field(default_factory=_ErrorTracking)


class HealthTracker:
    """
    Tracks provider health with circuit breaker pattern.

    Monitors success/failure rates, latency, and implements
    circuit breaker to prevent cascading failures.

    Example:
        tracker = HealthTracker(
            failure_threshold=5,
            recovery_timeout=30.0,
        )

        # Record metrics
        tracker.record_success("openai", latency_ms=150.0)
        tracker.record_failure("openai", Exception("Timeout"))

        # Check health before using provider
        if tracker.is_healthy("openai"):
            response = provider.complete(...)

        # Get detailed metrics
        metrics = tracker.get_metrics("openai")
        print(f"Success rate: {metrics.success_rate:.1%}")

    Circuit Breaker States:
        CLOSED: Normal operation, requests pass through
        OPEN: Too many failures, requests are blocked
        HALF_OPEN: Testing if provider has recovered
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        success_threshold: int = 2,
        recovery_timeout: float = 30.0,
        window_size: int = 100,
    ):
        """
        Initialize health tracker.

        Args:
            failure_threshold: Consecutive failures to open circuit
            success_threshold: Successes in half-open to close circuit
            recovery_timeout: Seconds before trying half-open state
            window_size: Number of requests for rolling statistics
        """
        self._failure_threshold = failure_threshold
        self._success_threshold = success_threshold
        self._recovery_timeout = recovery_timeout
        self._window_size = window_size
        self._stats: dict[str, _ProviderStats] = {}
        self._lock = Lock()

    def _get_stats(self, provider: str) -> _ProviderStats:
        """Get or create stats for a provider."""
        if provider not in self._stats:
            self._stats[provider] = _ProviderStats(latencies=deque(maxlen=self._window_size))
        return self._stats[provider]

    def record_success(self, provider: str, latency_ms: float) -> None:
        """
        Record a successful request.

        Args:
            provider: Provider identifier
            latency_ms: Request latency in milliseconds
        """
        with self._lock:
            stats = self._get_stats(provider)
            stats.latencies.append(latency_ms)
            stats.requests.successes += 1
            stats.requests.consecutive_failures = 0
            stats.errors.last_success = datetime.now(timezone.utc)

            # Handle circuit state transitions
            if stats.circuit.state == CircuitState.HALF_OPEN:
                stats.circuit.half_open_attempts += 1
                if stats.circuit.half_open_attempts >= self._success_threshold:
                    stats.circuit.state = CircuitState.CLOSED
                    stats.circuit.half_open_attempts = 0
            elif stats.circuit.state == CircuitState.OPEN:
                # Shouldn't happen, but handle gracefully
                stats.circuit.state = CircuitState.HALF_OPEN

    def record_failure(
        self,
        provider: str,
        error: Exception | None = None,
        latency_ms: float | None = None,
    ) -> None:
        """
        Record a failed request.

        Args:
            provider: Provider identifier
            error: The exception that occurred
            latency_ms: Request latency before failure (if available)
        """
        with self._lock:
            stats = self._get_stats(provider)
            if latency_ms is not None:
                stats.latencies.append(latency_ms)
            stats.requests.failures += 1
            stats.requests.consecutive_failures += 1
            stats.errors.last_failure = datetime.now(timezone.utc)
            stats.errors.last_error = str(error) if error else None

            # Handle circuit state transitions
            if stats.circuit.state == CircuitState.HALF_OPEN:
                # Failure in half-open -> back to open
                stats.circuit.state = CircuitState.OPEN
                stats.circuit.opened_at = datetime.now(timezone.utc)
                stats.circuit.half_open_attempts = 0
            elif stats.circuit.state == CircuitState.CLOSED:
                if stats.requests.consecutive_failures >= self._failure_threshold:
                    stats.circuit.state = CircuitState.OPEN
                    stats.circuit.opened_at = datetime.now(timezone.utc)

    def is_healthy(self, provider: str) -> bool:
        """
        Check if a provider should be used.

        Handles circuit state transitions from OPEN to HALF_OPEN
        after recovery timeout.

        Args:
            provider: Provider identifier

        Returns:
            True if provider can receive requests
        """
        with self._lock:
            stats = self._get_stats(provider)

            if stats.circuit.state == CircuitState.CLOSED:
                return True

            if stats.circuit.state == CircuitState.HALF_OPEN:
                return True  # Allow test requests

            if stats.circuit.state == CircuitState.OPEN:
                # Check if recovery timeout has passed
                if stats.circuit.opened_at:
                    elapsed = (datetime.now(timezone.utc) - stats.circuit.opened_at).total_seconds()
                    if elapsed >= self._recovery_timeout:
                        stats.circuit.state = CircuitState.HALF_OPEN
                        stats.circuit.half_open_attempts = 0
                        return True
                return False

            return True

    def get_metrics(self, provider: str) -> HealthMetrics:
        """
        Get health metrics for a provider.

        Args:
            provider: Provider identifier

        Returns:
            HealthMetrics with current statistics
        """
        with self._lock:
            stats = self._get_stats(provider)
            total = stats.requests.successes + stats.requests.failures

            # Calculate latency percentiles
            latencies = sorted(stats.latencies) if stats.latencies else [0.0]
            avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
            p95_idx = int(len(latencies) * 0.95)
            p99_idx = int(len(latencies) * 0.99)
            p95_latency = latencies[min(p95_idx, len(latencies) - 1)]
            p99_latency = latencies[min(p99_idx, len(latencies) - 1)]

            # Calculate success rate
            success_rate = stats.requests.successes / total if total > 0 else 1.0

            return HealthMetrics(
                name=provider,
                circuit_breaker=_CircuitBreakerMetrics(
                    state=stats.circuit.state,
                    consecutive_failures=stats.requests.consecutive_failures,
                    circuit_opened_at=stats.circuit.opened_at,
                ),
                requests=_RequestMetrics(
                    total_requests=total,
                    successful_requests=stats.requests.successes,
                    failed_requests=stats.requests.failures,
                    success_rate=success_rate,
                ),
                latency=_LatencyMetrics(
                    avg_latency_ms=avg_latency,
                    p95_latency_ms=p95_latency,
                    p99_latency_ms=p99_latency,
                ),
                errors=_ErrorMetrics(
                    last_success=stats.errors.last_success,
                    last_failure=stats.errors.last_failure,
                    last_error=stats.errors.last_error,
                ),
            )

    def get_all_metrics(self) -> dict[str, HealthMetrics]:
        """
        Get health metrics for all tracked providers.

        Returns:
            Dictionary mapping provider names to HealthMetrics
        """
        return {name: self.get_metrics(name) for name in self._stats}

    def reset(self, provider: str) -> None:
        """
        Reset health tracking for a provider.

        Args:
            provider: Provider identifier
        """
        with self._lock:
            if provider in self._stats:
                del self._stats[provider]

    def reset_all(self) -> None:
        """Reset health tracking for all providers."""
        with self._lock:
            self._stats.clear()

    def force_open(self, provider: str) -> None:
        """
        Force circuit to open state (for testing/manual intervention).

        Args:
            provider: Provider identifier
        """
        with self._lock:
            stats = self._get_stats(provider)
            stats.circuit.state = CircuitState.OPEN
            stats.circuit.opened_at = datetime.now(timezone.utc)

    def force_close(self, provider: str) -> None:
        """
        Force circuit to closed state (for testing/manual intervention).

        Args:
            provider: Provider identifier
        """
        with self._lock:
            stats = self._get_stats(provider)
            stats.circuit.state = CircuitState.CLOSED
            stats.requests.consecutive_failures = 0
            stats.circuit.half_open_attempts = 0


class _HealthTrackerRegistry:
    """Registry for managing the default health tracker."""

    _instance: ClassVar[HealthTracker | None] = None

    @classmethod
    def get(cls) -> HealthTracker:
        """Get the default global health tracker."""
        if cls._instance is None:
            cls._instance = HealthTracker()
        return cls._instance

    @classmethod
    def set(cls, tracker: HealthTracker) -> None:
        """Set the default global health tracker."""
        cls._instance = tracker


def get_health_tracker() -> HealthTracker:
    """Get the default global health tracker."""
    return _HealthTrackerRegistry.get()


def set_health_tracker(tracker: HealthTracker) -> None:
    """Set the default global health tracker."""
    _HealthTrackerRegistry.set(tracker)


__all__ = [
    "CircuitState",
    "HealthMetrics",
    "HealthTracker",
    "get_health_tracker",
    "set_health_tracker",
]
