"""
Provider Registry for centralized LLM provider management.

Provides a singleton registry for registering and retrieving
LLM providers with their configuration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .base import LLMProvider


@dataclass
class _PerformanceConfig:
    """Performance-related configuration."""

    priority: int = 0
    timeout: float = 30.0
    max_retries: int = 3


@dataclass
class _CostConfig:
    """Cost-related configuration."""

    cost_per_1k_input_tokens: float = 0.0
    cost_per_1k_output_tokens: float = 0.0


@dataclass
class _CapabilityConfig:
    """Capability-related configuration."""

    models: list[str] = field(default_factory=list)
    capabilities: set[str] = field(default_factory=lambda: {"completion", "embedding"})


@dataclass
class _RegistrationMetadata:
    """Registration and metadata tracking."""

    registered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProviderConfig:
    """Configuration for a registered LLM provider."""

    name: str
    provider: "LLMProvider"
    enabled: bool = True
    performance: _PerformanceConfig = field(default_factory=_PerformanceConfig)
    cost: _CostConfig = field(default_factory=_CostConfig)
    capability: _CapabilityConfig = field(default_factory=_CapabilityConfig)
    registry: _RegistrationMetadata = field(default_factory=_RegistrationMetadata)

    @property
    def priority(self) -> int:
        """Get priority."""
        return self.performance.priority

    @priority.setter
    def priority(self, value: int) -> None:
        """Set priority."""
        self.performance.priority = value

    @property
    def timeout(self) -> float:
        """Get timeout."""
        return self.performance.timeout

    @timeout.setter
    def timeout(self, value: float) -> None:
        """Set timeout."""
        self.performance.timeout = value

    @property
    def max_retries(self) -> int:
        """Get max retries."""
        return self.performance.max_retries

    @max_retries.setter
    def max_retries(self, value: int) -> None:
        """Set max retries."""
        self.performance.max_retries = value

    @property
    def cost_per_1k_input_tokens(self) -> float:
        """Get input token cost."""
        return self.cost.cost_per_1k_input_tokens

    @cost_per_1k_input_tokens.setter
    def cost_per_1k_input_tokens(self, value: float) -> None:
        """Set input token cost."""
        self.cost.cost_per_1k_input_tokens = value

    @property
    def cost_per_1k_output_tokens(self) -> float:
        """Get output token cost."""
        return self.cost.cost_per_1k_output_tokens

    @cost_per_1k_output_tokens.setter
    def cost_per_1k_output_tokens(self, value: float) -> None:
        """Set output token cost."""
        self.cost.cost_per_1k_output_tokens = value

    @property
    def models(self) -> list[str]:
        """Get supported models."""
        return self.capability.models

    @models.setter
    def models(self, value: list[str]) -> None:
        """Set supported models."""
        self.capability.models = value

    @property
    def capabilities(self) -> set[str]:
        """Get capabilities."""
        return self.capability.capabilities

    @capabilities.setter
    def capabilities(self, value: set[str]) -> None:
        """Set capabilities."""
        self.capability.capabilities = value

    @property
    def metadata(self) -> dict[str, Any]:
        """Get metadata."""
        return self.registry.metadata

    @metadata.setter
    def metadata(self, value: dict[str, Any]) -> None:
        """Set metadata."""
        self.registry.metadata = value

    @property
    def registered_at(self) -> datetime:
        """Get registration timestamp."""
        return self.registry.registered_at


class ProviderRegistry:
    """
    Singleton registry for LLM providers.

    Provides centralized management of provider configurations
    with support for priority ordering, capability filtering,
    and cost-based selection.

    Example:
        # Register providers
        ProviderRegistry.register(
            "openai",
            OpenAIProvider(),
            priority=1,
            cost_per_1k_input_tokens=0.03,
        )
        ProviderRegistry.register(
            "anthropic",
            AnthropicProvider(),
            priority=2,
            cost_per_1k_input_tokens=0.015,
        )

        # Get provider
        config = ProviderRegistry.get("openai")
        response = config.provider.complete("Hello")

        # List by capability
        providers = ProviderRegistry.list_with_capability("embedding")
    """

    _providers: dict[str, ProviderConfig] = {}

    @classmethod
    def register(
        cls,
        name: str,
        provider: "LLMProvider",
        *,
        priority: int = 0,
        timeout: float = 30.0,
        max_retries: int = 3,
        models: list[str] | None = None,
        **metadata: Any,
    ) -> ProviderConfig:
        """
        Register a provider with the registry.

        Args:
            name: Unique provider identifier
            provider: LLM provider instance
            priority: Selection priority (lower = higher priority)
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts
            models: List of supported model identifiers
            **metadata: Additional metadata (costs, capabilities, enabled, etc.)

        Returns:
            The created ProviderConfig
        """
        config = ProviderConfig(
            name=name,
            provider=provider,
            enabled=metadata.pop("enabled", True),
            performance=_PerformanceConfig(
                priority=priority,
                timeout=timeout,
                max_retries=max_retries,
            ),
            cost=_CostConfig(
                cost_per_1k_input_tokens=metadata.pop("cost_per_1k_input_tokens", 0.0),
                cost_per_1k_output_tokens=metadata.pop("cost_per_1k_output_tokens", 0.0),
            ),
            capability=_CapabilityConfig(
                models=models or [],
                capabilities=metadata.pop("capabilities", {"completion", "embedding"}),
            ),
            registry=_RegistrationMetadata(
                metadata=metadata,
            ),
        )
        cls._providers[name] = config
        return config

    @classmethod
    def unregister(cls, name: str) -> bool:
        """
        Remove a provider from the registry.

        Args:
            name: Provider identifier to remove

        Returns:
            True if provider was removed, False if not found
        """
        if name in cls._providers:
            del cls._providers[name]
            return True
        return False

    @classmethod
    def get(cls, name: str) -> ProviderConfig | None:
        """
        Get a provider configuration by name.

        Args:
            name: Provider identifier

        Returns:
            ProviderConfig if found, None otherwise
        """
        return cls._providers.get(name)

    @classmethod
    def get_or_raise(cls, name: str) -> ProviderConfig:
        """
        Get a provider configuration or raise an error.

        Args:
            name: Provider identifier

        Returns:
            ProviderConfig

        Raises:
            KeyError: If provider not found
        """
        config = cls._providers.get(name)
        if config is None:
            raise KeyError(f"Provider '{name}' not registered")
        return config

    @classmethod
    def list_all(cls) -> list[ProviderConfig]:
        """
        List all registered providers.

        Returns:
            List of all ProviderConfig instances
        """
        return list(cls._providers.values())

    @classmethod
    def list_enabled(cls) -> list[ProviderConfig]:
        """
        List all enabled providers.

        Returns:
            List of enabled ProviderConfig instances
        """
        return [c for c in cls._providers.values() if c.enabled]

    @classmethod
    def list_names(cls) -> list[str]:
        """
        List all registered provider names.

        Returns:
            List of provider identifiers
        """
        return list(cls._providers.keys())

    @classmethod
    def list_by_priority(cls, enabled_only: bool = True) -> list[ProviderConfig]:
        """
        List providers sorted by priority (ascending).

        Args:
            enabled_only: Only include enabled providers

        Returns:
            List of ProviderConfig instances sorted by priority
        """
        providers = cls.list_enabled() if enabled_only else cls.list_all()
        return sorted(providers, key=lambda c: c.priority)

    @classmethod
    def list_by_cost(cls, enabled_only: bool = True) -> list[ProviderConfig]:
        """
        List providers sorted by cost (ascending).

        Args:
            enabled_only: Only include enabled providers

        Returns:
            List of ProviderConfig instances sorted by input token cost
        """
        providers = cls.list_enabled() if enabled_only else cls.list_all()
        return sorted(providers, key=lambda c: c.cost_per_1k_input_tokens)

    @classmethod
    def list_with_capability(
        cls,
        capability: str,
        enabled_only: bool = True,
    ) -> list[ProviderConfig]:
        """
        List providers that support a specific capability.

        Args:
            capability: Required capability (e.g., "completion", "embedding")
            enabled_only: Only include enabled providers

        Returns:
            List of ProviderConfig instances with the capability
        """
        providers = cls.list_enabled() if enabled_only else cls.list_all()
        return [c for c in providers if capability in c.capabilities]

    @classmethod
    def list_with_model(
        cls,
        model: str,
        enabled_only: bool = True,
    ) -> list[ProviderConfig]:
        """
        List providers that support a specific model.

        Args:
            model: Model identifier
            enabled_only: Only include enabled providers

        Returns:
            List of ProviderConfig instances supporting the model
        """
        providers = cls.list_enabled() if enabled_only else cls.list_all()
        return [c for c in providers if model in c.models or not c.models]

    @classmethod
    def enable(cls, name: str) -> bool:
        """Enable a provider."""
        config = cls._providers.get(name)
        if config:
            config.enabled = True
            return True
        return False

    @classmethod
    def disable(cls, name: str) -> bool:
        """Disable a provider."""
        config = cls._providers.get(name)
        if config:
            config.enabled = False
            return True
        return False

    @classmethod
    def clear(cls) -> None:
        """Clear all registered providers."""
        cls._providers.clear()

    @classmethod
    def count(cls) -> int:
        """Return the number of registered providers."""
        return len(cls._providers)


__all__ = [
    "ProviderConfig",
    "ProviderRegistry",
]
