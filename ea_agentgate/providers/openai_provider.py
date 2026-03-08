"""OpenAI LLM provider implementation."""

from __future__ import annotations

from typing import Any, cast

from .base import LLMResponse
from .openai_common import (
    OpenAIClientFactory,
    build_chat_messages,
    handle_chat_completion_response,
    handle_embedding_response,
)


class OpenAIProvider:
    """
    OpenAI provider for completions and embeddings.

    Uses GPT-4o-mini by default for fast, cost-effective completions.
    Uses text-embedding-3-small for embeddings.

    Example:
        provider = OpenAIProvider()
        response = provider.complete("What is 2+2?", system="You are helpful.")
        embedding = provider.embed("Hello world")

        # With custom models
        provider = OpenAIProvider(
            model="gpt-4o",
            embedding_model="text-embedding-3-large",
        )
    """

    def __init__(
        self,
        client: Any | None = None,
        model: str = "gpt-4o-mini",
        embedding_model: str = "text-embedding-3-small",
        api_key: str | None = None,
        **client_kwargs: Any,
    ) -> None:
        """
        Initialize OpenAI provider.

        Args:
            client: Optional pre-configured OpenAI client
            model: Model for completions (default: gpt-4o-mini)
            embedding_model: Model for embeddings (default: text-embedding-3-small)
            api_key: OpenAI API key (uses OPENAI_API_KEY env var if not provided)
            **client_kwargs: Additional arguments for OpenAI client
        """
        self.model = model
        self.embedding_model = embedding_model

        if client:
            self._client = client
        else:
            self._client = self._create_client(api_key, **client_kwargs)

    def _create_client(self, api_key: str | None, **kwargs: Any) -> Any:
        """Create OpenAI client."""
        return OpenAIClientFactory.create_client(api_key, **kwargs)

    def complete(
        self,
        prompt: str,
        system: str | None = None,
        **kwargs: Any,
    ) -> LLMResponse:
        """
        Generate a completion using OpenAI.

        Args:
            prompt: The user message
            system: Optional system prompt
            **kwargs: Additional arguments (temperature, max_tokens, etc.)

        Returns:
            LLMResponse with generated content
        """
        messages = build_chat_messages(prompt, system)
        model = kwargs.pop("model", self.model)

        response = self._client.chat.completions.create(
            model=model,
            messages=cast(Any, messages),
            **kwargs,
        )

        return handle_chat_completion_response(response)

    def embed(self, text: str) -> list[float]:
        """
        Generate an embedding using OpenAI.

        Args:
            text: Text to embed

        Returns:
            Embedding vector as list of floats
        """
        response = self._client.embeddings.create(
            model=self.embedding_model,
            input=text,
        )

        return handle_embedding_response(response)


__all__ = ["OpenAIProvider"]
