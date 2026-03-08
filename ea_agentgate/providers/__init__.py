"""LLM provider abstractions for semantic features."""

from importlib import import_module
from typing import TYPE_CHECKING

# Core imports that don't require external dependencies
from .base import LLMProvider, LLMResponse
from .health import CircuitState, HealthMetrics, HealthTracker, get_health_tracker
from .registry import ProviderConfig, ProviderRegistry, _PerformanceConfig, _CostConfig
from .routing import (
    RoutingStrategy,
    FallbackStrategy,
    RoundRobinStrategy,
    CostOptimizedStrategy,
    LatencyOptimizedStrategy,
    RandomStrategy,
    get_strategy,
)


# Lazy imports for provider implementations (require external packages)
def __getattr__(name: str):
    """Lazy import providers that require external dependencies."""
    if name == "AsyncAnthropicProvider":
        module = import_module("ea_agentgate.providers.anthropic_async")
        return getattr(module, name)
    if name == "AnthropicProvider":
        module = import_module("ea_agentgate.providers.anthropic_provider")
        return getattr(module, name)
    if name == "AsyncOpenAIProvider":
        module = import_module("ea_agentgate.providers.openai_async")
        return getattr(module, name)
    if name == "OpenAIProvider":
        module = import_module("ea_agentgate.providers.openai_provider")
        return getattr(module, name)
    if name in ("AsyncGoogleProvider", "GoogleProvider"):
        module = import_module("ea_agentgate.providers.google_provider")
        return getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


if TYPE_CHECKING:
    from .anthropic_async import AsyncAnthropicProvider
    from .anthropic_provider import AnthropicProvider
    from .google_provider import AsyncGoogleProvider
    from .google_provider import GoogleProvider
    from .openai_async import AsyncOpenAIProvider
    from .openai_provider import OpenAIProvider

__all__ = [
    # Protocol interfaces
    "LLMProvider",
    "LLMResponse",
    # Registry
    "ProviderConfig",
    "ProviderRegistry",
    "_PerformanceConfig",
    "_CostConfig",
    # Health tracking
    "CircuitState",
    "HealthMetrics",
    "HealthTracker",
    "get_health_tracker",
    # Routing strategies
    "RoutingStrategy",
    "FallbackStrategy",
    "RoundRobinStrategy",
    "CostOptimizedStrategy",
    "LatencyOptimizedStrategy",
    "RandomStrategy",
    "get_strategy",
    # Sync implementations (lazy loaded)
    "OpenAIProvider",
    "AnthropicProvider",
    "GoogleProvider",
    # Async implementations (lazy loaded)
    "AsyncOpenAIProvider",
    "AsyncAnthropicProvider",
    "AsyncGoogleProvider",
]
