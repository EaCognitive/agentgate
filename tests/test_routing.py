"""Tests for Model Routing & Fallbacks (Feature 3)."""

from importlib import import_module
import sys
import time
from unittest.mock import MagicMock

import pytest

from ea_agentgate.client import (
    AgentGate,
    AllProvidersFailedError,
    CompletionResult,
    Metadata,
    Performance,
    TokenUsage,
    UniversalClient,
)
from ea_agentgate.providers import (
    CircuitState,
    CostOptimizedStrategy,
    FallbackStrategy,
    HealthTracker,
    ProviderConfig,
    ProviderRegistry,
    RandomStrategy,
    RoundRobinStrategy,
    _CostConfig,
    _PerformanceConfig,
    get_strategy,
)

# =============================================================================
# Provider Registry Tests
# =============================================================================


def test_provider_registry_register():
    """Test registering a provider."""

    # Clear any existing registrations
    ProviderRegistry.clear()

    mock_provider = MagicMock()
    config = ProviderRegistry.register(
        "test_provider",
        mock_provider,
        priority=1,
        cost_per_1k_input_tokens=0.01,
    )

    assert config.name == "test_provider"
    assert config.priority == 1
    assert config.cost_per_1k_input_tokens == 0.01
    assert config.enabled is True

    # Cleanup
    ProviderRegistry.clear()


def test_provider_registry_get():
    """Test retrieving a provider."""

    ProviderRegistry.clear()

    mock_provider = MagicMock()
    ProviderRegistry.register("test", mock_provider)

    config = ProviderRegistry.get("test")
    assert config is not None
    assert config.name == "test"

    # Non-existent provider
    assert ProviderRegistry.get("nonexistent") is None

    ProviderRegistry.clear()


def test_provider_registry_list_by_priority():
    """Test listing providers by priority."""

    ProviderRegistry.clear()

    ProviderRegistry.register("low", MagicMock(), priority=10)
    ProviderRegistry.register("high", MagicMock(), priority=1)
    ProviderRegistry.register("medium", MagicMock(), priority=5)

    providers = ProviderRegistry.list_by_priority()
    names = [p.name for p in providers]

    assert names == ["high", "medium", "low"]

    ProviderRegistry.clear()


def test_provider_registry_list_by_cost():
    """Test listing providers by cost."""

    ProviderRegistry.clear()

    ProviderRegistry.register("expensive", MagicMock(), cost_per_1k_input_tokens=0.10)
    ProviderRegistry.register("cheap", MagicMock(), cost_per_1k_input_tokens=0.001)
    ProviderRegistry.register("medium", MagicMock(), cost_per_1k_input_tokens=0.03)

    providers = ProviderRegistry.list_by_cost()
    names = [p.name for p in providers]

    assert names == ["cheap", "medium", "expensive"]

    ProviderRegistry.clear()


def test_provider_registry_enable_disable():
    """Test enabling and disabling providers."""

    ProviderRegistry.clear()

    ProviderRegistry.register("test", MagicMock())

    # Disable
    ProviderRegistry.disable("test")
    assert ProviderRegistry.get("test").enabled is False
    assert len(ProviderRegistry.list_enabled()) == 0

    # Enable
    ProviderRegistry.enable("test")
    assert ProviderRegistry.get("test").enabled is True
    assert len(ProviderRegistry.list_enabled()) == 1

    ProviderRegistry.clear()


# =============================================================================
# Health Tracker Tests
# =============================================================================


def test_health_tracker_record_success():
    """Test recording successful requests."""

    tracker = HealthTracker()
    tracker.record_success("provider1", latency_ms=100.0)
    tracker.record_success("provider1", latency_ms=150.0)

    metrics = tracker.get_metrics("provider1")
    assert metrics.successful_requests == 2
    assert metrics.failed_requests == 0
    assert metrics.avg_latency_ms > 0
    assert metrics.success_rate == 1.0


def test_health_tracker_record_failure():
    """Test recording failed requests."""

    tracker = HealthTracker()
    tracker.record_failure("provider1", Exception("Test error"))
    tracker.record_failure("provider1", Exception("Another error"))

    metrics = tracker.get_metrics("provider1")
    assert metrics.failed_requests == 2
    assert metrics.success_rate == 0.0
    assert metrics.last_error == "Another error"


def test_health_tracker_circuit_breaker():
    """Test circuit breaker opens after threshold failures."""

    tracker = HealthTracker(failure_threshold=3)

    # Record failures
    for _ in range(3):
        tracker.record_failure("provider1", Exception("Error"))

    metrics = tracker.get_metrics("provider1")
    assert metrics.state == CircuitState.OPEN
    assert not tracker.is_healthy("provider1")


def test_health_tracker_circuit_recovery():
    """Test circuit breaker recovery after timeout."""

    # Very short recovery timeout for testing
    tracker = HealthTracker(failure_threshold=2, recovery_timeout=0.1)

    # Open the circuit
    tracker.record_failure("provider1", Exception("Error"))
    tracker.record_failure("provider1", Exception("Error"))

    assert not tracker.is_healthy("provider1")

    # Wait for recovery timeout
    time.sleep(0.15)

    # Should be in half-open state now
    assert tracker.is_healthy("provider1")
    metrics = tracker.get_metrics("provider1")
    assert metrics.state == CircuitState.HALF_OPEN


def test_health_tracker_success_closes_circuit():
    """Test that success in half-open state closes circuit."""

    tracker = HealthTracker(failure_threshold=2, success_threshold=1, recovery_timeout=0.01)

    # Open circuit
    tracker.record_failure("provider1", Exception("Error"))
    tracker.record_failure("provider1", Exception("Error"))

    # Wait and allow half-open

    time.sleep(0.02)
    tracker.is_healthy("provider1")  # Triggers state check

    # Success in half-open should close
    tracker.record_success("provider1", latency_ms=100.0)
    metrics = tracker.get_metrics("provider1")
    assert metrics.state == CircuitState.CLOSED


# =============================================================================
# Routing Strategy Tests
# =============================================================================


def test_fallback_strategy():
    """Test fallback strategy yields providers in order."""

    providers = [
        ProviderConfig(
            name="first",
            provider=MagicMock(),
            performance=_PerformanceConfig(priority=1),
        ),
        ProviderConfig(
            name="second",
            provider=MagicMock(),
            performance=_PerformanceConfig(priority=2),
        ),
        ProviderConfig(
            name="third",
            provider=MagicMock(),
            performance=_PerformanceConfig(priority=3),
        ),
    ]

    strategy = FallbackStrategy(order=["second", "first", "third"])
    selected = list(strategy.select(providers))
    names = [p.name for p in selected]

    # Should follow specified order
    assert names == ["second", "first", "third"]


def test_fallback_strategy_skips_disabled():
    """Test fallback strategy skips disabled providers."""

    providers = [
        ProviderConfig(name="enabled", provider=MagicMock(), enabled=True),
        ProviderConfig(name="disabled", provider=MagicMock(), enabled=False),
    ]

    strategy = FallbackStrategy(order=["disabled", "enabled"])
    selected = list(strategy.select(providers))
    names = [p.name for p in selected]

    assert names == ["enabled"]


def test_cost_optimized_strategy():
    """Test cost-optimized strategy orders by cost."""

    providers = [
        ProviderConfig(
            name="expensive",
            provider=MagicMock(),
            cost=_CostConfig(cost_per_1k_input_tokens=0.10),
        ),
        ProviderConfig(
            name="cheap",
            provider=MagicMock(),
            cost=_CostConfig(cost_per_1k_input_tokens=0.001),
        ),
        ProviderConfig(
            name="medium",
            provider=MagicMock(),
            cost=_CostConfig(cost_per_1k_input_tokens=0.03),
        ),
    ]

    strategy = CostOptimizedStrategy()
    selected = list(strategy.select(providers))
    names = [p.name for p in selected]

    assert names == ["cheap", "medium", "expensive"]


def test_round_robin_strategy():
    """Test round-robin strategy distributes across providers."""

    providers = [
        ProviderConfig(name="a", provider=MagicMock()),
        ProviderConfig(name="b", provider=MagicMock()),
        ProviderConfig(name="c", provider=MagicMock()),
    ]

    strategy = RoundRobinStrategy()

    # First call
    first = [p.name for p in strategy.select(providers)]
    # Second call should start from different position
    second = [p.name for p in strategy.select(providers)]

    assert len(first) == 3
    assert len(second) == 3
    # Order should be rotated
    assert first[0] != second[0] or first[1] != second[1]


def test_random_strategy():
    """Test random strategy includes all providers."""

    providers = [
        ProviderConfig(name="a", provider=MagicMock()),
        ProviderConfig(name="b", provider=MagicMock()),
        ProviderConfig(name="c", provider=MagicMock()),
    ]

    strategy = RandomStrategy()
    selected = list(strategy.select(providers))

    assert len(selected) == 3
    assert set(p.name for p in selected) == {"a", "b", "c"}


def test_get_strategy_factory():
    """Test strategy factory function."""

    fallback = get_strategy("fallback", order=["a", "b"])
    assert isinstance(fallback, FallbackStrategy)

    cost = get_strategy("cost")
    assert isinstance(cost, CostOptimizedStrategy)


def test_get_strategy_invalid():
    """Test strategy factory raises on invalid name."""

    with pytest.raises(ValueError, match="Unknown strategy"):
        get_strategy("invalid_strategy")


# =============================================================================
# Universal Client Tests
# =============================================================================


def test_universal_client_init():
    """Test UniversalClient initialization."""

    client = UniversalClient(
        strategy="fallback",
        order=["openai", "anthropic"],
        timeout=10.0,
    )

    assert client.timeout == 10.0
    assert client.strategy.name == "FallbackStrategy"


def test_universal_client_with_providers():
    """Test UniversalClient with explicit providers."""

    mock_provider = MagicMock()
    providers = [
        ProviderConfig(name="mock", provider=mock_provider),
    ]

    client = UniversalClient(providers=providers)
    assert "mock" in client.providers


def test_completion_result_dataclass():
    """Test CompletionResult contains expected fields."""

    metadata = Metadata(model="gpt-5.2", provider="openai", cost=0.001)
    tokens = TokenUsage(input_tokens=10, output_tokens=5)
    performance = Performance(latency_ms=150.0)

    result = CompletionResult(
        content="Hello, world!",
        metadata=metadata,
        tokens=tokens,
        performance=performance,
    )

    assert result.content == "Hello, world!"
    assert result.metadata.model == "gpt-5.2"
    assert result.metadata.provider == "openai"
    assert result.total_tokens == 15
    assert result.performance.latency_ms == 150.0


def test_all_providers_failed_error():
    """Test AllProvidersFailedError exception."""

    failures = [
        ("openai", Exception("Rate limited")),
        ("anthropic", Exception("Timeout")),
    ]

    error = AllProvidersFailedError("All failed", failures)

    assert "openai" in str(error)
    assert "Rate limited" in str(error)
    assert "anthropic" in str(error)
    assert "Timeout" in str(error)


def test_agentgate_factory():
    """Test AgentGate factory creates clients."""

    client = AgentGate.client(
        strategy="cost",
        timeout=5.0,
    )

    assert client.timeout == 5.0


def test_universal_client_health_check():
    """Test health check returns provider status."""

    mock_provider = MagicMock()
    providers = [
        ProviderConfig(name="test", provider=mock_provider),
    ]

    client = UniversalClient(providers=providers)
    health = client.health_check()

    assert "test" in health
    assert "healthy" in health["test"]
    assert "success_rate" in health["test"]


# =============================================================================
# Google Provider Tests
# =============================================================================


def test_google_provider_init():
    """Test GoogleProvider initialization."""
    # Mock google.generativeai before importing
    mock_genai = MagicMock()
    sys.modules["google"] = MagicMock()
    sys.modules["google.generativeai"] = mock_genai

    try:
        # Remove cached module if present
        if "ea_agentgate.providers.google_provider" in sys.modules:
            del sys.modules["ea_agentgate.providers.google_provider"]

        provider_module = import_module("ea_agentgate.providers.google_provider")
        google_provider = getattr(provider_module, "GoogleProvider")

        provider = google_provider(
            api_key="test-key",
            model="gemini-3-pro",
        )

        assert provider.model == "gemini-3-pro"
        assert provider.provider_name == "google"
    finally:
        # Clean up mocked modules
        sys.modules.pop("google.generativeai", None)
        sys.modules.pop("google", None)
        sys.modules.pop("ea_agentgate.providers.google_provider", None)


def test_google_provider_get_cost():
    """Test GoogleProvider cost retrieval."""
    # Mock google.generativeai before importing
    mock_genai = MagicMock()
    sys.modules["google"] = MagicMock()
    sys.modules["google.generativeai"] = mock_genai

    try:
        # Remove cached module if present
        if "ea_agentgate.providers.google_provider" in sys.modules:
            del sys.modules["ea_agentgate.providers.google_provider"]

        provider_module = import_module("ea_agentgate.providers.google_provider")
        google_provider = getattr(provider_module, "GoogleProvider")

        provider = google_provider(model="gemini-3-flash")
        input_cost, output_cost = provider.get_cost_per_1k_tokens()

        assert input_cost > 0
        assert output_cost > 0
    finally:
        # Clean up mocked modules
        sys.modules.pop("google.generativeai", None)
        sys.modules.pop("google", None)
        sys.modules.pop("ea_agentgate.providers.google_provider", None)


# =============================================================================
# Integration Tests
# =============================================================================


def test_registry_with_routing():
    """Test provider registry works with routing strategies."""

    ProviderRegistry.clear()

    ProviderRegistry.register("primary", MagicMock(), priority=1)
    ProviderRegistry.register("backup", MagicMock(), priority=2)

    providers = ProviderRegistry.list_enabled()
    strategy = FallbackStrategy(order=["primary", "backup"])

    selected = list(strategy.select(providers))
    names = [p.name for p in selected]

    assert "primary" in names
    assert "backup" in names

    ProviderRegistry.clear()


def test_health_tracker_with_routing():
    """Test health tracker integrates with routing."""

    tracker = HealthTracker(failure_threshold=2)

    # Mark primary as unhealthy
    tracker.record_failure("primary", Exception("Error"))
    tracker.record_failure("primary", Exception("Error"))

    providers = [
        ProviderConfig(name="primary", provider=MagicMock()),
        ProviderConfig(name="backup", provider=MagicMock()),
    ]

    strategy = FallbackStrategy(order=["primary", "backup"], health_tracker=tracker)
    selected = list(strategy.select(providers))
    names = [p.name for p in selected]

    # Primary should be skipped due to circuit open
    assert names == ["backup"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
