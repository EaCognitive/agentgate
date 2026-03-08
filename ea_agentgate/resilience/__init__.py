"""Resilience patterns for agentgate middleware.

This module provides circuit breakers, retry logic, and failure handling
for building robust AI applications.
"""

from __future__ import annotations

from .circuit_breaker import CircuitBreaker, CircuitBreakerError, CircuitState

__all__ = [
    "CircuitBreaker",
    "CircuitBreakerError",
    "CircuitState",
]
