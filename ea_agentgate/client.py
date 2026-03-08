"""
Universal LLM Client with intelligent routing and automatic fallbacks.

Provides a unified interface for multiple LLM providers with:
- Automatic failover when providers fail
- Multiple routing strategies (fallback, round-robin, cost, latency)
- Health tracking with circuit breaker pattern
- Unified response format
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, cast
from collections.abc import Callable

from .providers.health import HealthTracker, get_health_tracker
from .providers.registry import ProviderConfig, ProviderRegistry
from .providers.routing import (
    RoutingStrategy,
    get_strategy,
)

if TYPE_CHECKING:
    from .providers.base import LLMProvider


class AllProvidersFailedError(Exception):
    """Raised when all providers fail to handle a request."""

    def __init__(
        self,
        message: str,
        failures: list[tuple[str, Exception]],
    ):
        super().__init__(message)
        self.failures = failures

    def __str__(self) -> str:
        failures_str = "\n".join(f"  - {name}: {error}" for name, error in self.failures)
        return f"{self.args[0]}\nProvider failures:\n{failures_str}"


@dataclass
class TokenUsage:
    """Token usage statistics."""

    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        """Calculate total tokens from input and output tokens."""
        return self.input_tokens + self.output_tokens


@dataclass
class Performance:
    """Performance metrics."""

    latency_ms: float = 0.0


@dataclass
class Metadata:
    """Completion metadata."""

    provider: str
    model: str
    finish_reason: str = "stop"
    fallback_used: bool = False
    providers_tried: list[str] = field(default_factory=list)
    raw_response: Any = None
    cost: float = 0.0


@dataclass
class CompletionResult:
    """Result of a completion request with metadata."""

    content: str
    metadata: Metadata
    tokens: TokenUsage = field(default_factory=TokenUsage)
    performance: Performance = field(default_factory=Performance)

    @property
    def total_tokens(self) -> int:
        """Calculate total tokens from input and output tokens."""
        return self.tokens.total_tokens


@dataclass
class ClientCallbacks:
    """Callbacks for client events."""

    on_fallback: Callable[[str, str, Exception], None] | None = None
    on_success: Callable[[str, CompletionResult], None] | None = None
    on_failure: Callable[[str, Exception], None] | None = None


class UniversalClient:
    """
    Universal LLM client with routing and automatic fallbacks.

    Provides a unified interface for multiple LLM providers,
    automatically handling failures with intelligent routing.

    Example:
        # Basic usage with fallback
        client = UniversalClient(
            strategy="fallback",
            order=["openai", "anthropic", "google"],
        )
        result = client.complete("Explain machine learning")

        # Cost-optimized routing
        client = UniversalClient(strategy="cost")
        result = client.complete("Simple question")  # Uses cheapest provider

        # With custom providers
        client = UniversalClient(
            providers=[
                ProviderConfig(name="primary", provider=OpenAIProvider()),
                ProviderConfig(name="backup", provider=AnthropicProvider()),
            ]
        )

    Routing Strategies:
        - fallback: Try providers in order until one succeeds
        - round_robin: Distribute load across providers
        - cost: Select cheapest provider
        - latency: Select fastest provider
        - random: Random selection
    """

    # pylint: disable-next=too-many-arguments,too-many-positional-arguments
    def __init__(
        self,
        strategy: str | RoutingStrategy = "fallback",
        providers: list[ProviderConfig] | None = None,
        order: list[str] | None = None,
        timeout: float = 30.0,
        max_retries: int = 3,
        health_tracker: HealthTracker | None = None,
        on_fallback: Callable[[str, str, Exception], None] | None = None,
        on_success: Callable[[str, CompletionResult], None] | None = None,
        on_failure: Callable[[str, Exception], None] | None = None,
    ):
        """
        Initialize UniversalClient.

        Args:
            strategy: Routing strategy name or instance
            providers: List of provider configurations (uses registry if None)
            order: Provider order for fallback strategy
            timeout: Request timeout in seconds
            max_retries: Max retries per provider
            health_tracker: Health tracker instance (creates default if None)
            on_fallback: Callback when falling back to another provider
            on_success: Callback on successful completion
            on_failure: Callback on provider failure
        """
        self._timeout = timeout
        self._max_retries = max_retries
        self._health_tracker = health_tracker or get_health_tracker()
        self.callbacks = ClientCallbacks(on_fallback, on_success, on_failure)
        self._providers = providers or []
        self._failures: list[tuple[str, Exception]] = []

        # Setup routing strategy
        if isinstance(strategy, str):
            kwargs = {}
            if order:
                kwargs["order"] = order
            self._strategy = get_strategy(
                strategy,
                health_tracker=self._health_tracker,
                **kwargs,
            )
        else:
            self._strategy = strategy

    def _get_providers(self) -> list[ProviderConfig]:
        """Get providers from registry or instance list."""
        if self._providers:
            return self._providers
        return ProviderRegistry.list_enabled()

    def complete(
        self,
        prompt: str,
        system: str | None = None,
        **kwargs: Any,
    ) -> CompletionResult:
        """
        Generate a completion with automatic fallback.

        Args:
            prompt: The user prompt
            system: Optional system instruction
            **kwargs: Additional provider-specific arguments

        Returns:
            CompletionResult with the generated content

        Raises:
            AllProvidersFailedError: If all providers fail
        """
        providers = self._get_providers()
        self._failures = []
        providers_tried: list[str] = []
        fallback_used = False

        for config in self._strategy.select(providers):
            providers_tried.append(config.name)

            if len(providers_tried) > 1:
                fallback_used = True

            try:
                result = self._try_provider(config, prompt, system, **kwargs)
                result.metadata.fallback_used = fallback_used
                result.metadata.providers_tried = providers_tried

                if self.callbacks.on_success:
                    self.callbacks.on_success(config.name, result)

                return result

            except (TimeoutError, OSError, RuntimeError) as e:
                self._handle_failure(config, e)
                if len(providers_tried) > 1 and self.callbacks.on_fallback:
                    prev_provider = providers_tried[-2]
                    self.callbacks.on_fallback(prev_provider, config.name, e)
                continue

        raise AllProvidersFailedError(
            "All providers failed to complete the request",
            self._failures,
        )

    async def acomplete(
        self,
        prompt: str,
        system: str | None = None,
        **kwargs: Any,
    ) -> CompletionResult:
        """
        Async completion with automatic fallback.

        Args:
            prompt: The user prompt
            system: Optional system instruction
            **kwargs: Additional provider-specific arguments

        Returns:
            CompletionResult with the generated content

        Raises:
            AllProvidersFailedError: If all providers fail
        """
        providers = self._get_providers()
        self._failures = []
        providers_tried: list[str] = []
        fallback_used = False

        for config in self._strategy.select(providers):
            providers_tried.append(config.name)

            if len(providers_tried) > 1:
                fallback_used = True

            try:
                result = await self._try_provider_async(config, prompt, system, **kwargs)
                result.metadata.fallback_used = fallback_used
                result.metadata.providers_tried = providers_tried

                if self.callbacks.on_success:
                    self.callbacks.on_success(config.name, result)

                return result

            except (TimeoutError, OSError, RuntimeError) as e:
                self._handle_failure(config, e)
                if len(providers_tried) > 1 and self.callbacks.on_fallback:
                    prev_provider = providers_tried[-2]
                    self.callbacks.on_fallback(prev_provider, config.name, e)
                continue

        raise AllProvidersFailedError(
            "All providers failed to complete the request",
            self._failures,
        )

    def _try_provider(
        self,
        config: ProviderConfig,
        prompt: str,
        system: str | None,
        **kwargs: Any,
    ) -> CompletionResult:
        """Try a single provider with retries."""
        last_error: Exception | None = None
        timeout = kwargs.pop("timeout", config.timeout or self._timeout)
        max_retries = kwargs.pop("max_retries", config.max_retries or self._max_retries)

        for attempt in range(max_retries):
            try:
                start_time = time.time()
                response = config.provider.complete(prompt, system, timeout=timeout, **kwargs)
                latency_ms = (time.time() - start_time) * 1000

                # Record success
                self._health_tracker.record_success(config.name, latency_ms)

                # Calculate cost
                input_cost = config.cost_per_1k_input_tokens * (response.input_tokens / 1000)
                output_cost = config.cost_per_1k_output_tokens * (response.output_tokens / 1000)
                total_cost = input_cost + output_cost

                return CompletionResult(
                    content=response.content,
                    metadata=Metadata(
                        provider=config.name,
                        model=response.model,
                        finish_reason=response.finish_reason or "stop",
                        raw_response=response.raw_response,
                        cost=total_cost,
                    ),
                    tokens=TokenUsage(
                        input_tokens=response.input_tokens,
                        output_tokens=response.output_tokens,
                    ),
                    performance=Performance(latency_ms=latency_ms),
                )

            except (TimeoutError, OSError, RuntimeError) as e:
                last_error = e
                if attempt < max_retries - 1:
                    continue

        # Record failure after all retries exhausted
        if last_error:
            self._health_tracker.record_failure(config.name, last_error)
            raise last_error
        raise RuntimeError("Unexpected error in provider")

    def _calculate_cost(self, config: ProviderConfig, response: CompletionResult) -> float:
        """Calculate the cost of a completion."""
        input_cost = config.cost_per_1k_input_tokens * (response.tokens.input_tokens / 1000)
        output_cost = config.cost_per_1k_output_tokens * (response.tokens.output_tokens / 1000)
        return input_cost + output_cost

    async def _try_provider_async(
        self,
        config: ProviderConfig,
        prompt: str,
        system: str | None,
        **kwargs: Any,
    ) -> CompletionResult:
        """Try a single provider asynchronously with retries."""
        last_error: Exception | None = None
        timeout = kwargs.pop("timeout", config.timeout or self._timeout)
        max_retries = kwargs.pop("max_retries", config.max_retries or self._max_retries)

        for attempt in range(max_retries):
            try:
                start_time = time.time()

                # Use async method if available
                if hasattr(config.provider, "acomplete"):
                    response = await asyncio.wait_for(
                        cast(Any, config.provider).acomplete(prompt, system, **kwargs),
                        timeout=timeout,
                    )
                else:
                    # Fall back to sync in thread pool
                    response = await asyncio.wait_for(
                        asyncio.to_thread(config.provider.complete, prompt, system, **kwargs),
                        timeout=timeout,
                    )

                latency_ms = (time.time() - start_time) * 1000
                self._health_tracker.record_success(config.name, latency_ms)

                result = CompletionResult(
                    content=response.content,
                    metadata=Metadata(
                        provider=config.name,
                        model=response.model,
                        finish_reason=response.finish_reason or "stop",
                        raw_response=response.raw_response,
                    ),
                    tokens=TokenUsage(
                        input_tokens=response.input_tokens,
                        output_tokens=response.output_tokens,
                    ),
                    performance=Performance(latency_ms=latency_ms),
                )
                result.metadata.cost = self._calculate_cost(config, result)
                return result

            except asyncio.TimeoutError:
                last_error = TimeoutError(f"Request to {config.name} timed out")
            except (OSError, RuntimeError) as e:
                last_error = e

            if attempt < max_retries - 1:
                continue

        if last_error:
            self._health_tracker.record_failure(config.name, last_error)
            raise last_error
        raise RuntimeError("Unexpected error in provider")

    def _handle_failure(self, config: ProviderConfig, error: Exception) -> None:
        """Handle a provider failure."""
        self._failures.append((config.name, error))
        if self.callbacks.on_failure:
            self.callbacks.on_failure(config.name, error)

    def embed(self, text: str, **kwargs: Any) -> list[float]:
        """
        Generate embeddings with automatic fallback.

        Args:
            text: Text to embed
            **kwargs: Additional provider-specific arguments

        Returns:
            List of embedding floats

        Raises:
            AllProvidersFailedError: If all providers fail
        """
        providers = self._get_providers()
        # Filter to providers with embedding capability
        providers = [p for p in providers if "embedding" in p.capabilities]

        self._failures = []

        for config in self._strategy.select(providers):
            try:
                start_time = time.time()
                embedding = config.provider.embed(text, **kwargs)
                latency_ms = (time.time() - start_time) * 1000
                self._health_tracker.record_success(config.name, latency_ms)
                return embedding
            except (TimeoutError, OSError, RuntimeError) as e:
                self._health_tracker.record_failure(config.name, e)
                self._failures.append((config.name, e))
                continue

        raise AllProvidersFailedError(
            "All providers failed to generate embeddings",
            self._failures,
        )

    async def aembed(self, text: str, **kwargs: Any) -> list[float]:
        """
        Async embedding with automatic fallback.

        Args:
            text: Text to embed
            **kwargs: Additional provider-specific arguments

        Returns:
            List of embedding floats

        Raises:
            AllProvidersFailedError: If all providers fail
        """
        providers = self._get_providers()
        providers = [p for p in providers if "embedding" in p.capabilities]

        self._failures = []

        for config in self._strategy.select(providers):
            try:
                start_time = time.time()

                if hasattr(config.provider, "aembed"):
                    embedding = await cast(Any, config.provider).aembed(text, **kwargs)
                else:
                    embedding = await asyncio.to_thread(config.provider.embed, text, **kwargs)

                latency_ms = (time.time() - start_time) * 1000
                self._health_tracker.record_success(config.name, latency_ms)
                return cast(list[float], embedding)
            except (TimeoutError, OSError, RuntimeError) as e:
                self._health_tracker.record_failure(config.name, e)
                self._failures.append((config.name, e))
                continue

        raise AllProvidersFailedError(
            "All providers failed to generate embeddings",
            self._failures,
        )

    def health_check(self) -> dict[str, Any]:
        """
        Check health of all providers.

        Returns:
            Dictionary with health status for each provider
        """
        providers = self._get_providers()
        result: dict[str, Any] = {}

        for config in providers:
            metrics = self._health_tracker.get_metrics(config.name)
            result[config.name] = {
                "healthy": metrics.is_healthy,
                "state": metrics.state.value,
                "success_rate": metrics.success_rate,
                "avg_latency_ms": metrics.avg_latency_ms,
                "total_requests": metrics.total_requests,
                "last_error": metrics.last_error,
            }

        return result

    @property
    def providers(self) -> list[str]:
        """Return list of provider names."""
        return [c.name for c in self._get_providers()]

    @property
    def strategy(self) -> RoutingStrategy:
        """Return the current routing strategy."""
        return self._strategy

    @property
    def timeout(self) -> float:
        """Return the configured request timeout."""
        return self._timeout


class AgentGate:
    """
    Factory for creating configured UniversalClient instances.

    Example:
        # Quick client with defaults
        client = AgentGate.Client()

        # Configured client
        client = AgentGate.Client(
            strategy="cost",
            timeout=10.0,
        )
    """

    @staticmethod
    def client(
        strategy: str = "fallback",
        order: list[str] | None = None,
        timeout: float = 30.0,
        **kwargs: Any,
    ) -> UniversalClient:
        """
        Create a configured UniversalClient.

        Args:
            strategy: Routing strategy name
            order: Provider order for fallback strategy
            timeout: Request timeout in seconds
            **kwargs: Additional UniversalClient arguments

        Returns:
            Configured UniversalClient instance
        """
        return UniversalClient(
            strategy=strategy,
            order=order,
            timeout=timeout,
            **kwargs,
        )

    @staticmethod
    def register_provider(
        name: str,
        provider: "LLMProvider",
        **kwargs: Any,
    ) -> ProviderConfig:
        """
        Register a provider in the global registry.

        Args:
            name: Provider identifier
            provider: LLM provider instance
            **kwargs: Provider configuration

        Returns:
            ProviderConfig for the registered provider
        """
        return ProviderRegistry.register(name, provider, **kwargs)

    @staticmethod
    def get_health_tracker() -> HealthTracker:
        """Get the global health tracker."""
        return get_health_tracker()


__all__ = [
    "AllProvidersFailedError",
    "CompletionResult",
    "UniversalClient",
    "AgentGate",
]
