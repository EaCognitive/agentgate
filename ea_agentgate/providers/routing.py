"""
Routing Strategies for intelligent provider selection.

Provides multiple strategies for selecting LLM providers:
- Fallback: Try providers in order until one succeeds
- RoundRobin: Distribute load across providers
- CostOptimized: Select cheapest provider
- LatencyOptimized: Select fastest provider
"""

from __future__ import annotations

import random
from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from .registry import ProviderConfig
    from .health import HealthTracker


class RoutingStrategy(Protocol):
    """
    Protocol for provider routing strategies.

    Strategies determine which provider to use for a given request.
    """

    def select(
        self,
        providers: list[ProviderConfig],
        _context: dict[str, Any] | None = None,
    ) -> Iterator[ProviderConfig]:
        """
        Yield providers in order of preference.

        Args:
            providers: Available provider configurations
            context: Optional context for selection decisions

        Yields:
            ProviderConfig instances in preferred order
        """
        raise NotImplementedError

    @property
    def name(self) -> str:
        """Return the strategy name."""
        return self.__class__.__name__


class FallbackStrategy(RoutingStrategy):
    """
    Try providers in a specified order until one succeeds.

    This is the default strategy, implementing a simple
    primary/backup pattern.

    Example:
        strategy = FallbackStrategy(
            order=["openai", "anthropic", "google"]
        )
        # Will try openai first, then anthropic, then google
    """

    def __init__(
        self,
        order: list[str] | None = None,
        health_tracker: "HealthTracker | None" = None,
    ):
        """
        Initialize fallback strategy.

        Args:
            order: Provider names in order of preference
            health_tracker: Optional health tracker for filtering unhealthy providers
        """
        # Note: super().__init__() not called because Protocol is not a proper base class
        # and does not have an __init__ to call
        self._order = order or []
        self._health_tracker = health_tracker

    def select(
        self,
        providers: list["ProviderConfig"],
        _context: dict[str, Any] | None = None,
    ) -> Iterator["ProviderConfig"]:
        """Yield providers in fallback order."""
        provider_map = {p.name: p for p in providers}

        # First, yield providers in specified order
        for name in self._order:
            if name in provider_map:
                config = provider_map[name]
                if self._is_available(config):
                    yield config

        # Then, yield any remaining providers by priority
        for config in sorted(providers, key=lambda c: c.priority):
            if config.name not in self._order and self._is_available(config):
                yield config

    def _is_available(self, config: "ProviderConfig") -> bool:
        """Check if provider is available for use."""
        if not config.enabled:
            return False
        if self._health_tracker:
            return self._health_tracker.is_healthy(config.name)
        return True


class RoundRobinStrategy(RoutingStrategy):
    """
    Distribute requests evenly across providers.

    Useful for load balancing when multiple providers
    have similar capabilities and costs.

    Example:
        strategy = RoundRobinStrategy()
        # Will cycle through all available providers
    """

    def __init__(
        self,
        health_tracker: "HealthTracker | None" = None,
        weights: dict[str, int] | None = None,
    ):
        """
        Initialize round-robin strategy.

        Args:
            health_tracker: Optional health tracker for filtering
            weights: Optional weights for weighted distribution
        """
        super().__init__()
        self._health_tracker = health_tracker
        self._weights = weights or {}
        self._index = 0

    def select(
        self,
        providers: list["ProviderConfig"],
        _context: dict[str, Any] | None = None,
    ) -> Iterator["ProviderConfig"]:
        """Yield providers in round-robin order."""
        available = [p for p in providers if self._is_available(p)]
        if not available:
            return

        # Apply weights by repeating providers
        weighted_list: list["ProviderConfig"] = []
        for config in available:
            weight = self._weights.get(config.name, 1)
            weighted_list.extend([config] * weight)

        if not weighted_list:
            return

        # Start from current index
        n = len(weighted_list)
        start = self._index % n

        # Yield all providers starting from current position
        for i in range(n):
            idx = (start + i) % n
            yield weighted_list[idx]

        # Advance index for next call
        self._index = (start + 1) % n

    def _is_available(self, config: "ProviderConfig") -> bool:
        """Check if provider is available for use."""
        if not config.enabled:
            return False
        if self._health_tracker:
            return self._health_tracker.is_healthy(config.name)
        return True


class CostOptimizedStrategy(RoutingStrategy):
    """
    Select providers based on cost (cheapest first).

    Useful for minimizing API costs while maintaining
    fallback capability to more expensive providers.

    Example:
        strategy = CostOptimizedStrategy()
        # Will try cheapest provider first
    """

    def __init__(
        self,
        health_tracker: "HealthTracker | None" = None,
        cost_type: str = "input",  # "input", "output", or "total"
    ):
        """
        Initialize cost-optimized strategy.

        Args:
            health_tracker: Optional health tracker for filtering
            cost_type: Which cost to optimize ("input", "output", "total")
        """
        super().__init__()
        self._health_tracker = health_tracker
        self._cost_type = cost_type

    def select(
        self,
        providers: list["ProviderConfig"],
        _context: dict[str, Any] | None = None,
    ) -> Iterator["ProviderConfig"]:
        """Yield providers in cost order (cheapest first)."""
        available = [p for p in providers if self._is_available(p)]

        def get_cost(config: "ProviderConfig") -> float:
            """Return the relevant cost metric for the given provider."""
            if self._cost_type == "input":
                return config.cost_per_1k_input_tokens
            if self._cost_type == "output":
                return config.cost_per_1k_output_tokens
            # total
            return config.cost_per_1k_input_tokens + config.cost_per_1k_output_tokens

        yield from sorted(available, key=get_cost)

    def _is_available(self, config: "ProviderConfig") -> bool:
        """Check if provider is available for use."""
        if not config.enabled:
            return False
        if self._health_tracker:
            return self._health_tracker.is_healthy(config.name)
        return True


class LatencyOptimizedStrategy(RoutingStrategy):
    """
    Select providers based on observed latency (fastest first).

    Uses health tracker metrics to order providers by
    their recent average latency.

    Example:
        strategy = LatencyOptimizedStrategy(
            health_tracker=tracker
        )
        # Will try fastest provider first
    """

    def __init__(
        self,
        health_tracker: "HealthTracker",
        percentile: str = "avg",  # "avg", "p95", "p99"
    ):
        """
        Initialize latency-optimized strategy.

        Args:
            health_tracker: Health tracker with latency metrics
            percentile: Which latency metric to use
        """
        super().__init__()
        self._health_tracker = health_tracker
        self._percentile = percentile

    def select(
        self,
        providers: list["ProviderConfig"],
        _context: dict[str, Any] | None = None,
    ) -> Iterator["ProviderConfig"]:
        """Yield providers in latency order (fastest first)."""
        available = [p for p in providers if self._is_available(p)]

        def get_latency(config: "ProviderConfig") -> float:
            """Return the relevant latency metric for the given provider."""
            metrics = self._health_tracker.get_metrics(config.name)
            if self._percentile == "p95":
                return metrics.p95_latency_ms
            if self._percentile == "p99":
                return metrics.p99_latency_ms
            return metrics.avg_latency_ms

        yield from sorted(available, key=get_latency)

    def _is_available(self, config: "ProviderConfig") -> bool:
        """Check if provider is available for use."""
        if not config.enabled:
            return False
        return self._health_tracker.is_healthy(config.name)


class RandomStrategy(RoutingStrategy):
    """
    Select providers randomly.

    Useful for chaos testing or when no preference exists.

    Example:
        strategy = RandomStrategy()
        # Will try providers in random order
    """

    def __init__(
        self,
        health_tracker: "HealthTracker | None" = None,
        weights: dict[str, float] | None = None,
    ):
        """
        Initialize random strategy.

        Args:
            health_tracker: Optional health tracker for filtering
            weights: Optional weights for biased selection
        """
        super().__init__()
        self._health_tracker = health_tracker
        self._weights = weights or {}

    def select(
        self,
        providers: list["ProviderConfig"],
        _context: dict[str, Any] | None = None,
    ) -> Iterator["ProviderConfig"]:
        """Yield providers in random order."""
        available = [p for p in providers if self._is_available(p)]

        if self._weights:
            # Weighted random shuffle
            weights = [self._weights.get(p.name, 1.0) for p in available]
            shuffled = []
            remaining = list(zip(available, weights))
            while remaining:
                total = sum(w for _, w in remaining)
                r = random.uniform(0, total)
                cumulative: float = 0.0
                for i, (config, weight) in enumerate(remaining):
                    cumulative += weight
                    if r <= cumulative:
                        shuffled.append(config)
                        remaining.pop(i)
                        break
            yield from shuffled
        else:
            # Simple random shuffle
            shuffled = available.copy()
            random.shuffle(shuffled)
            yield from shuffled

    def _is_available(self, config: "ProviderConfig") -> bool:
        """Check if provider is available for use."""
        if not config.enabled:
            return False
        if self._health_tracker:
            return self._health_tracker.is_healthy(config.name)
        return True


def get_strategy(
    name: str,
    health_tracker: "HealthTracker | None" = None,
    **kwargs: Any,
) -> RoutingStrategy:
    """
    Get a routing strategy by name.

    Args:
        name: Strategy name ("fallback", "round_robin", "cost", "latency", "random")
        health_tracker: Optional health tracker
        **kwargs: Additional strategy-specific arguments

    Returns:
        Configured RoutingStrategy instance

    Raises:
        ValueError: If strategy name is unknown
    """
    strategies: dict[str, Callable[..., RoutingStrategy]] = {
        "fallback": FallbackStrategy,
        "round_robin": RoundRobinStrategy,
        "cost": CostOptimizedStrategy,
        "cost_optimized": CostOptimizedStrategy,
        "latency": LatencyOptimizedStrategy,
        "latency_optimized": LatencyOptimizedStrategy,
        "random": RandomStrategy,
    }

    if name not in strategies:
        raise ValueError(f"Unknown strategy: {name}. Available: {list(strategies.keys())}")

    strategy_factory = strategies[name]

    # Latency strategy requires health tracker
    if name in ("latency", "latency_optimized") and health_tracker is None:
        raise ValueError("Latency strategy requires a health tracker")

    if health_tracker:
        return strategy_factory(health_tracker=health_tracker, **kwargs)
    return strategy_factory(**kwargs)


__all__ = [
    "RoutingStrategy",
    "FallbackStrategy",
    "RoundRobinStrategy",
    "CostOptimizedStrategy",
    "LatencyOptimizedStrategy",
    "RandomStrategy",
    "get_strategy",
]
