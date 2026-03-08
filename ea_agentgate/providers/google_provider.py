"""
Google Gemini provider implementation.

Provides integration with Google's Gemini models (gemini-3-pro, gemini-3-flash).
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from importlib import import_module
from types import ModuleType
from typing import Any, cast

from .base import LLMProvider, LLMResponse

genai: ModuleType | None
try:
    genai = import_module("google.generativeai")
except ImportError:  # pragma: no cover - optional dependency
    genai = None


@dataclass
class GeminiConfig:
    """Configuration for Google Gemini provider."""

    api_key: str | None = None
    model: str = "gemini-3-flash"
    max_tokens: int = 4096
    temperature: float = 0.7
    top_p: float = 0.95
    timeout: float = 30.0


class GoogleProvider(LLMProvider):
    """
    Google Gemini provider for completions and embeddings.

    Example:
        provider = GoogleProvider(
            api_key="your-api-key",
            model="gemini-3-pro",
        )

        response = provider.complete("Explain quantum computing")
        print(response.content)

    Supported models:
        - gemini-3-pro: Most capable model
        - gemini-3-flash: Fast, efficient model
    """

    # Model cost estimates (per 1K tokens)
    MODEL_COSTS = {
        "gemini-3-pro": {"input": 0.00125, "output": 0.005},
        "gemini-3-flash": {"input": 0.000075, "output": 0.0003},
    }

    def __init__(
        self,
        api_key: str | None = None,
        *,
        model: str = "gemini-3-flash",
        max_tokens: int = 4096,
        temperature: float = 0.7,
        timeout: float = 30.0,
    ):
        """
        Initialize Google Gemini provider.

        Args:
            api_key: Google API key (defaults to GOOGLE_API_KEY env var)
            model: Model identifier
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature (0.0-2.0)
            timeout: Request timeout in seconds
        """
        self._api_key = api_key or os.environ.get("GOOGLE_API_KEY")
        self._model = model
        self._max_tokens = max_tokens
        self._temperature = temperature
        self._timeout = timeout
        self._client: Any | None = None

    def _get_client(self) -> Any:
        """Get or create the Gemini client."""
        if genai is None:
            raise ImportError("google-generativeai is required for GoogleProvider")
        if self._client is None:
            if self._api_key:
                genai.configure(api_key=self._api_key)

            self._client = genai.GenerativeModel(self._model)
        return self._client

    def complete(
        self,
        prompt: str,
        system: str | None = None,
        **kwargs: Any,
    ) -> LLMResponse:
        """
        Generate a completion using Gemini.

        Args:
            prompt: The user prompt
            system: Optional system instruction
            **kwargs: Additional generation parameters

        Returns:
            LLMResponse with the generated content
        """
        client = self._get_client()

        # Build generation config
        generation_config = {
            "max_output_tokens": kwargs.get("max_tokens", self._max_tokens),
            "temperature": kwargs.get("temperature", self._temperature),
            "top_p": kwargs.get("top_p", 0.95),
        }

        # Combine system and user prompts
        full_prompt = f"{system}\n\n{prompt}" if system else prompt

        try:
            response = client.generate_content(
                full_prompt,
                generation_config=generation_config,
            )

            # Extract content
            content = response.text if hasattr(response, "text") else str(response)

            # Estimate token usage
            input_tokens = int(len(full_prompt.split()) * 1.3)  # Rough estimate
            output_tokens = int(len(content.split()) * 1.3)
            usage = {
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "total_tokens": input_tokens + output_tokens,
            }

            return LLMResponse(
                content=content,
                model=self._model,
                usage=usage,
                metadata={"provider": "google"},
                finish_reason="stop",
                raw_response=response,
            )

        except Exception as e:
            raise RuntimeError(f"Gemini completion failed: {e}") from e

    async def acomplete(
        self,
        prompt: str,
        system: str | None = None,
        **kwargs: Any,
    ) -> LLMResponse:
        """
        Async completion using Gemini.

        Args:
            prompt: The user prompt
            system: Optional system instruction
            **kwargs: Additional generation parameters

        Returns:
            LLMResponse with the generated content
        """
        client = self._get_client()

        generation_config = {
            "max_output_tokens": kwargs.get("max_tokens", self._max_tokens),
            "temperature": kwargs.get("temperature", self._temperature),
            "top_p": kwargs.get("top_p", 0.95),
        }

        full_prompt = f"{system}\n\n{prompt}" if system else prompt

        try:
            response = await client.generate_content_async(
                full_prompt,
                generation_config=generation_config,
            )

            content = response.text if hasattr(response, "text") else str(response)

            input_tokens = int(len(full_prompt.split()) * 1.3)
            output_tokens = int(len(content.split()) * 1.3)
            usage = {
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "total_tokens": input_tokens + output_tokens,
            }

            return LLMResponse(
                content=content,
                model=self._model,
                usage=usage,
                metadata={"provider": "google"},
                finish_reason="stop",
                raw_response=response,
            )

        except Exception as e:
            raise RuntimeError(f"Gemini async completion failed: {e}") from e

    def embed(self, text: str, **kwargs: Any) -> list[float]:
        """
        Generate embeddings using Gemini.

        Args:
            text: Text to embed
            **kwargs: Additional parameters

        Returns:
            List of embedding floats
        """
        try:
            if genai is None:
                raise ImportError("google-generativeai is required for GoogleProvider.embed")
            if self._api_key:
                genai.configure(api_key=self._api_key)

            model = kwargs.get("model", "models/embedding-001")
            result = genai.embed_content(
                model=model,
                content=text,
                task_type="retrieval_document",
            )

            embedding = result.get("embedding")
            if not isinstance(embedding, list):
                raise RuntimeError("Gemini embedding response payload is malformed")
            return [float(value) for value in cast(list[Any], embedding)]

        except Exception as e:
            raise RuntimeError(f"Gemini embedding failed: {e}") from e

    async def aembed(self, text: str, **kwargs: Any) -> list[float]:
        """
        Async embedding generation.

        Note: google-generativeai doesn't have native async embed,
        so this falls back to sync implementation.
        """
        return await asyncio.to_thread(self.embed, text, **kwargs)

    @property
    def model(self) -> str:
        """Return the current model."""
        return self._model

    @property
    def provider_name(self) -> str:
        """Return the provider name."""
        return "google"

    def get_cost_per_1k_tokens(self) -> tuple[float, float]:
        """
        Get cost per 1K tokens (input, output).

        Returns:
            Tuple of (input_cost, output_cost)
        """
        costs = self.MODEL_COSTS.get(self._model, {"input": 0.0, "output": 0.0})
        return costs["input"], costs["output"]


class AsyncGoogleProvider(GoogleProvider):
    """
    Async-optimized Google Gemini provider.

    Provides the same interface as GoogleProvider but
    optimized for async contexts.
    """

    def is_async_native(self) -> bool:
        """Return True as this provider prefers async."""
        return True


__all__ = [
    "GeminiConfig",
    "GoogleProvider",
    "AsyncGoogleProvider",
]
