"""Anthropic LLM provider implementation."""

from __future__ import annotations

from importlib import import_module
from typing import Any, cast

from .anthropic_base import build_llm_response, handle_embedding_delegation
from .base import LLMResponse


def _resolve_anthropic_client_class() -> type[Any]:
    """Resolve the optional Anthropic client class lazily."""
    try:
        anthropic_module = import_module("anthropic")
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise ImportError("anthropic package is required for AnthropicProvider") from exc
    client_class = getattr(anthropic_module, "Anthropic", None)
    if client_class is None:
        raise ImportError("anthropic package is required for AnthropicProvider")
    return cast(type[Any], client_class)


class AnthropicProvider:
    """
    Anthropic provider for completions.

    Uses Claude 3.5 Haiku by default for fast, cost-effective completions.
    Note: Anthropic doesn't provide embedding models, so this provider
    delegates embedding to a configurable embedding provider.

    Example:
        provider = AnthropicProvider()
        response = provider.complete("What is 2+2?", system="You are helpful.")

        # With custom model
        provider = AnthropicProvider(model="claude-sonnet-4-20250514")

        # With embedding support via OpenAI
        from ea_agentgate.providers import OpenAIProvider
        openai = OpenAIProvider()
        provider = AnthropicProvider(embedding_provider=openai)
        embedding = provider.embed("Hello world")  # Uses OpenAI embeddings
    """

    def __init__(
        self,
        client: Any | None = None,
        model: str = "claude-3-5-haiku-latest",
        api_key: str | None = None,
        embedding_provider: Any | None = None,
        **client_kwargs: Any,
    ) -> None:
        """
        Initialize Anthropic provider.

        Args:
            client: Optional pre-configured Anthropic client
            model: Model for completions (default: claude-3-5-haiku-latest)
            api_key: Anthropic API key (uses ANTHROPIC_API_KEY env var if not provided)
            embedding_provider: Provider for embeddings (Anthropic doesn't have embeddings)
            **client_kwargs: Additional arguments for Anthropic client
        """
        self.model = model
        self._embedding_provider = embedding_provider

        if client:
            self._client = client
        else:
            self._client = self._create_client(api_key, **client_kwargs)

    def _create_client(self, api_key: str | None, **kwargs: Any) -> Any:
        """Create Anthropic client."""
        client_class = _resolve_anthropic_client_class()
        return client_class(api_key=api_key, **kwargs)

    def complete(
        self,
        prompt: str,
        system: str | None = None,
        **kwargs: Any,
    ) -> LLMResponse:
        """
        Generate a completion using Anthropic.

        Args:
            prompt: The user message
            system: Optional system prompt
            **kwargs: Additional arguments (temperature, max_tokens, etc.)

        Returns:
            LLMResponse with generated content
        """
        model = kwargs.pop("model", self.model)
        max_tokens = kwargs.pop("max_tokens", 1024)

        create_kwargs: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }

        if system:
            create_kwargs["system"] = system

        create_kwargs.update(kwargs)

        response = self._client.messages.create(**create_kwargs)

        return build_llm_response(response)

    def embed(self, text: str) -> list[float]:
        """
        Generate an embedding.

        Anthropic doesn't provide embeddings, so this delegates to
        a configured embedding provider.

        Args:
            text: Text to embed

        Returns:
            Embedding vector as list of floats

        Raises:
            RuntimeError: If no embedding provider is configured
        """
        provider = self._embedding_provider
        handle_embedding_delegation(provider, "OpenAIProvider", sync=True)
        if provider is None:
            raise RuntimeError("Embedding provider is required for AnthropicProvider.embed")
        embedding = provider.embed(text)
        if not isinstance(embedding, list):
            raise RuntimeError("Embedding provider returned malformed embedding payload")
        return [float(value) for value in cast(list[Any], embedding)]


__all__ = ["AnthropicProvider"]
