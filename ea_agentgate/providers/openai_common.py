"""Shared OpenAI provider utilities and response handling."""

from __future__ import annotations

from typing import Any, cast

from .base import LLMResponse

_async_openai_cls: type[Any] | None
_openai_cls: type[Any] | None
try:
    from openai import AsyncOpenAI as _imported_async_openai
    from openai import OpenAI as _imported_openai

    _async_openai_cls = _imported_async_openai
    _openai_cls = _imported_openai
except ImportError:  # pragma: no cover - optional dependency
    _async_openai_cls = None
    _openai_cls = None


def build_chat_messages(
    prompt: str,
    system: str | None = None,
) -> list[dict[str, str]]:
    """
    Build OpenAI chat completion messages list.

    Args:
        prompt: The user message
        system: Optional system prompt

    Returns:
        List of message dictionaries for OpenAI API
    """
    messages: list[dict[str, str]] = []

    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    return messages


def handle_chat_completion_response(response: Any) -> LLMResponse:
    """
    Convert OpenAI chat completion response to LLMResponse.

    Handles extraction of content, usage statistics, and metadata
    from the OpenAI response object.

    Args:
        response: ChatCompletion response from OpenAI API

    Returns:
        LLMResponse with standardized format

    Raises:
        RuntimeError: If response has no choices
    """
    if not response.choices:
        raise RuntimeError("OpenAI returned empty response (no choices)")

    choice = response.choices[0]
    content = choice.message.content or ""

    usage = {}
    if response.usage:
        usage = {
            "input_tokens": response.usage.prompt_tokens,
            "output_tokens": response.usage.completion_tokens,
            "total_tokens": response.usage.total_tokens,
        }

    return LLMResponse(
        content=content,
        model=response.model,
        usage=usage,
        metadata={
            "finish_reason": choice.finish_reason,
            "id": response.id,
        },
        finish_reason=choice.finish_reason,
        raw_response=response,
    )


def handle_embedding_response(response: Any) -> list[float]:
    """
    Extract embedding vector from OpenAI embedding response.

    Args:
        response: Embedding response from OpenAI API

    Returns:
        Embedding vector as list of floats

    Raises:
        RuntimeError: If response has no data
    """
    if not response.data:
        raise RuntimeError("OpenAI returned empty embedding response")

    embedding = response.data[0].embedding
    if not isinstance(embedding, list):
        raise RuntimeError("OpenAI embedding response payload is malformed")
    return [float(value) for value in cast(list[Any], embedding)]


class OpenAIClientFactory:
    """Factory for creating OpenAI clients with consistent configuration."""

    @staticmethod
    def create_client(api_key: str | None, **kwargs: Any) -> Any:
        """
        Create OpenAI client.

        Args:
            api_key: OpenAI API key (uses OPENAI_API_KEY env var if not provided)
            **kwargs: Additional arguments for OpenAI client

        Returns:
            Configured OpenAI client
        """
        if _openai_cls is None:
            raise ImportError("openai package is required for OpenAI provider support")
        return _openai_cls(api_key=api_key, **kwargs)

    @staticmethod
    def get_default_timeout() -> float:
        """Get the default timeout for OpenAI API requests.

        Returns:
            Default timeout in seconds
        """
        return 60.0


class AsyncOpenAIClientFactory:
    """Factory for creating async OpenAI clients with consistent configuration."""

    @staticmethod
    def create_client(api_key: str | None, **kwargs: Any) -> Any:
        """
        Create AsyncOpenAI client.

        Args:
            api_key: OpenAI API key (uses OPENAI_API_KEY env var if not provided)
            **kwargs: Additional arguments for AsyncOpenAI client

        Returns:
            Configured AsyncOpenAI client
        """
        if _async_openai_cls is None:
            raise ImportError("openai package is required for AsyncOpenAI provider support")
        return _async_openai_cls(api_key=api_key, **kwargs)

    @staticmethod
    def get_default_timeout() -> float:
        """Get the default timeout for AsyncOpenAI API requests.

        Returns:
            Default timeout in seconds
        """
        return 60.0


__all__ = [
    "build_chat_messages",
    "handle_chat_completion_response",
    "handle_embedding_response",
    "OpenAIClientFactory",
    "AsyncOpenAIClientFactory",
]
