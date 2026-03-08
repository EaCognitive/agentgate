"""Async OpenAI LLM provider implementation."""

from __future__ import annotations

from typing import Any, cast

from .base import LLMResponse
from .openai_common import (
    AsyncOpenAIClientFactory,
    build_chat_messages,
    handle_chat_completion_response,
    handle_embedding_response,
)


class AsyncOpenAIProvider:
    """
    Async OpenAI provider for completions and embeddings.

    Uses AsyncOpenAI client for non-blocking I/O, suitable for
    high-concurrency applications like FastAPI services.

    Example:
        provider = AsyncOpenAIProvider()
        response = await provider.acomplete("What is 2+2?", system="You are helpful.")
        embedding = await provider.aembed("Hello world")

        # With custom models
        provider = AsyncOpenAIProvider(
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
        Initialize async OpenAI provider.

        Args:
            client: Optional pre-configured AsyncOpenAI client
            model: Model for completions (default: gpt-4o-mini)
            embedding_model: Model for embeddings (default: text-embedding-3-small)
            api_key: OpenAI API key (uses OPENAI_API_KEY env var if not provided)
            **client_kwargs: Additional arguments for AsyncOpenAI client
        """
        self.model = model
        self.embedding_model = embedding_model

        if client:
            self._client = client
        else:
            self._client = self._create_client(api_key, **client_kwargs)

    def _create_client(self, api_key: str | None, **kwargs: Any) -> Any:
        """Create AsyncOpenAI client."""
        return AsyncOpenAIClientFactory.create_client(api_key, **kwargs)

    async def acomplete(
        self,
        prompt: str,
        system: str | None = None,
        **kwargs: Any,
    ) -> LLMResponse:
        """
        Async generate a completion using OpenAI.

        Args:
            prompt: The user message
            system: Optional system prompt
            **kwargs: Additional arguments (temperature, max_tokens, etc.)

        Returns:
            LLMResponse with generated content
        """
        messages = build_chat_messages(prompt, system)
        model = kwargs.pop("model", self.model)

        response = await self._client.chat.completions.create(
            model=model,
            messages=cast(Any, messages),
            **kwargs,
        )

        return handle_chat_completion_response(response)

    async def aembed(self, text: str) -> list[float]:
        """
        Async generate an embedding using OpenAI.

        Args:
            text: Text to embed

        Returns:
            Embedding vector as list of floats
        """
        response = await self._client.embeddings.create(
            model=self.embedding_model,
            input=text,
        )

        return handle_embedding_response(response)


__all__ = ["AsyncOpenAIProvider"]
