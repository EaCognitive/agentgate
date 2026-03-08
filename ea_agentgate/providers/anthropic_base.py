"""Base utilities for Anthropic provider implementations."""

from __future__ import annotations

from typing import Any

from .base import LLMResponse


def extract_text_from_response(response: Any) -> str:
    """
    Extract text content from Anthropic API response.

    Args:
        response: Response object from Anthropic API

    Returns:
        Concatenated text content from all text blocks

    Raises:
        RuntimeError: If response has no content blocks
    """
    if not response.content:
        raise RuntimeError("Anthropic returned empty response (no content blocks)")

    content = ""
    for block in response.content:
        if hasattr(block, "text"):
            content += block.text

    return content


def build_llm_response(response: Any) -> LLMResponse:
    """
    Build LLMResponse from Anthropic API response.

    Args:
        response: Response object from Anthropic API

    Returns:
        LLMResponse object with extracted content and metadata
    """
    content = extract_text_from_response(response)

    usage = {
        "input_tokens": response.usage.input_tokens,
        "output_tokens": response.usage.output_tokens,
        "total_tokens": response.usage.input_tokens + response.usage.output_tokens,
    }

    return LLMResponse(
        content=content,
        model=response.model,
        usage=usage,
        metadata={
            "stop_reason": response.stop_reason,
            "id": response.id,
        },
        finish_reason=response.stop_reason,
        raw_response=response,
    )


def handle_embedding_delegation(
    embedding_provider: Any | None, provider_name: str, sync: bool = True
) -> None:
    """
    Validate that an embedding provider is configured.

    Args:
        embedding_provider: The configured embedding provider
        provider_name: Name of the embedding provider for error message
        sync: Whether this is for sync (True) or async (False) provider

    Raises:
        RuntimeError: If no embedding provider is configured
    """
    if embedding_provider is None:
        sync_text = "" if sync else "Async"
        raise RuntimeError(
            f"Anthropic doesn't provide embeddings. "
            f"Configure an embedding_provider (e.g., {provider_name}) "
            f"when creating {sync_text}AnthropicProvider."
        )


__all__ = [
    "extract_text_from_response",
    "build_llm_response",
    "handle_embedding_delegation",
]
