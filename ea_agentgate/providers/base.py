"""Base LLM provider protocol."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass
class LLMResponse:
    """Response from an LLM provider."""

    content: str
    model: str
    usage: dict[str, int] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    finish_reason: str | None = None
    raw_response: Any | None = None

    @property
    def input_tokens(self) -> int:
        """Get input token count."""
        return self.usage.get("input_tokens", self.usage.get("prompt_tokens", 0))

    @property
    def output_tokens(self) -> int:
        """Get output token count."""
        return self.usage.get("output_tokens", self.usage.get("completion_tokens", 0))

    @property
    def total_tokens(self) -> int:
        """Get total token count."""
        return self.usage.get("total_tokens", self.input_tokens + self.output_tokens)


@runtime_checkable
class LLMProvider(Protocol):
    """
    Protocol for LLM providers.

    Providers must implement both completion and embedding methods.
    Used by SemanticValidator and SemanticCache middleware.

    Example:
        class MyProvider:
            def complete(self, prompt: str, system: str | None = None, **kwargs) -> LLMResponse:
                # Call your LLM API
                return LLMResponse(content="...", model="my-model")

            def embed(self, text: str) -> list[float]:
                # Call your embedding API
                return [0.1, 0.2, ...]
    """

    def complete(
        self,
        prompt: str,
        system: str | None = None,
        **kwargs: Any,
    ) -> LLMResponse:
        """
        Generate a completion from the LLM.

        Args:
            prompt: The user prompt/message
            system: Optional system prompt
            **kwargs: Provider-specific arguments (temperature, max_tokens, etc.)

        Returns:
            LLMResponse with generated content
        """
        raise NotImplementedError

    def embed(self, text: str) -> list[float]:
        """
        Generate an embedding vector for the text.

        Args:
            text: Text to embed

        Returns:
            List of floats representing the embedding vector
        """
        raise NotImplementedError


__all__ = [
    "LLMProvider",
    "LLMResponse",
]
