"""Backend protocols for distributed state management."""

from __future__ import annotations

from importlib import import_module
from typing import Any

from .memory import (
    MemoryCacheBackend,
    MemoryCostBackend,
    MemoryPIIVaultBackend,
    MemoryRateLimitBackend,
)
from .protocols import (
    AsyncCacheBackend,
    AsyncCostBackend,
    AsyncPIIVaultBackend,
    AsyncRateLimitBackend,
    CacheBackend,
    CostBackend,
    PIIVaultBackend,
    RateLimitBackend,
)
from .types import CacheEntry, PIIEntry

_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "RedisRateLimitBackend": ("ea_agentgate.backends.redis", "RedisRateLimitBackend"),
    "RedisCostBackend": ("ea_agentgate.backends.redis", "RedisCostBackend"),
    "RedisCacheBackend": ("ea_agentgate.backends.redis", "RedisCacheBackend"),
    "RedisPIIVaultBackend": ("ea_agentgate.backends.redis", "RedisPIIVaultBackend"),
    "create_redis_client": ("ea_agentgate.backends.redis", "create_redis_client"),
    "AsyncRedisRateLimitBackend": (
        "ea_agentgate.backends.redis_async",
        "AsyncRedisRateLimitBackend",
    ),
    "AsyncRedisCostBackend": (
        "ea_agentgate.backends.redis_async",
        "AsyncRedisCostBackend",
    ),
    "AsyncRedisCacheBackend": (
        "ea_agentgate.backends.redis_async",
        "AsyncRedisCacheBackend",
    ),
    "AsyncRedisPIIVaultBackend": (
        "ea_agentgate.backends.redis_async",
        "AsyncRedisPIIVaultBackend",
    ),
    "create_async_redis_client": (
        "ea_agentgate.backends.redis_async",
        "create_async_redis_client",
    ),
    "CompliantPIIVaultBackend": (
        "ea_agentgate.backends.compliant",
        "CompliantPIIVaultBackend",
    ),
    "GuardrailBackend": ("ea_agentgate.backends.guardrail_backend", "GuardrailBackend"),
    "AsyncGuardrailBackend": (
        "ea_agentgate.backends.guardrail_backend",
        "AsyncGuardrailBackend",
    ),
    "MemoryGuardrailBackend": (
        "ea_agentgate.backends.guardrail_backend",
        "MemoryGuardrailBackend",
    ),
    "TransitionResult": ("ea_agentgate.backends.guardrail_backend", "TransitionResult"),
    "RedisGuardrailBackend": (
        "ea_agentgate.backends.guardrail_backend",
        "RedisGuardrailBackend",
    ),
    "AsyncRedisGuardrailBackend": (
        "ea_agentgate.backends.guardrail_backend",
        "AsyncRedisGuardrailBackend",
    ),
}

__all__ = [
    "CacheEntry",
    "PIIEntry",
    "RateLimitBackend",
    "CostBackend",
    "CacheBackend",
    "PIIVaultBackend",
    "AsyncRateLimitBackend",
    "AsyncCostBackend",
    "AsyncCacheBackend",
    "AsyncPIIVaultBackend",
    "MemoryRateLimitBackend",
    "MemoryCostBackend",
    "MemoryCacheBackend",
    "MemoryPIIVaultBackend",
    *_LAZY_EXPORTS,
]


def __getattr__(name: str) -> Any:
    """Resolve backend exports lazily."""
    if name in _LAZY_EXPORTS:
        module_name, attr_name = _LAZY_EXPORTS[name]
        module = import_module(module_name)
        return getattr(module, attr_name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
