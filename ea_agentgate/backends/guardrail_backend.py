"""Guardrail backend -- re-export facade for backward compatibility.

All concrete implementations have been split into sub-modules:
- guardrail_types: TransitionResult, protocols, _ConstraintViolation
- guardrail_memory: MemoryGuardrailBackend
- guardrail_redis: RedisGuardrailBackend, AsyncRedisGuardrailBackend
"""

from ea_agentgate.backends.guardrail_types import (
    AsyncGuardrailBackend,
    GuardrailBackend,
    TransitionResult,
)
from ea_agentgate.backends.guardrail_memory import (
    MemoryGuardrailBackend,
)
from ea_agentgate.backends.guardrail_redis import (
    AsyncRedisGuardrailBackend,
    RedisGuardrailBackend,
)

__all__ = [
    "TransitionResult",
    "GuardrailBackend",
    "AsyncGuardrailBackend",
    "MemoryGuardrailBackend",
    "RedisGuardrailBackend",
    "AsyncRedisGuardrailBackend",
]
