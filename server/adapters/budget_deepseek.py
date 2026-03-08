"""DeepSeek adapter compatibility module with lightweight budget-aware semantics.

This module restores the `server.adapters.budget_deepseek` import path used by
benchmark and journey tests while providing a concrete OpenAI-compatible DeepSeek
client implementation.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

try:
    from openai import OpenAI, OpenAIError
except ImportError:
    from openai import OpenAI

    class OpenAIError(Exception):
        """Fallback OpenAI-compatible error for older SDK releases."""


class DeepSeekProviderError(RuntimeError):
    """Raised when the upstream DeepSeek provider returns an unrecoverable error."""


class DeepSeekRateLimitError(DeepSeekProviderError):
    """Raised when the upstream provider responds with a rate-limit condition."""


class BudgetExceededError(RuntimeError):
    """Raised when caller-level budget policy denies the request."""

    def __init__(self, message: str, *, retry_after_seconds: int = 0) -> None:
        super().__init__(message)
        self.retry_after_seconds = max(0, retry_after_seconds)


@dataclass
class RequestResult:
    """Structured response metadata for completion requests."""

    text: str
    total_tokens: int
    cost_cents: int
    response_id: str | None = None


class DeepSeekClient:
    """Simple DeepSeek completion client with bounded retry behavior."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str = "deepseek-chat",
        max_retries: int = 2,
        base_backoff_seconds: float = 0.5,
        timeout_seconds: int = 30,
        budget_limit_cents: int | None = None,
    ) -> None:
        resolved_key = api_key or os.environ.get("DEEPSEEK_API_KEY", "")
        if not resolved_key:
            raise ValueError("DEEPSEEK_API_KEY is required for DeepSeekClient.")

        self._client = OpenAI(api_key=resolved_key, base_url="https://api.deepseek.com")
        self._model = model
        self._max_retries = max(0, max_retries)
        self._base_backoff_seconds = max(0.0, base_backoff_seconds)
        self._timeout_seconds = max(1, timeout_seconds)
        self._budget_limit_cents = budget_limit_cents

    @property
    def model(self) -> str:
        """Expose the configured model name for observability and testing."""
        return self._model

    def complete(
        self,
        *,
        user_id: str,
        prompt: str,
        max_tokens: int = 512,
        temperature: float = 0.2,
    ) -> RequestResult:
        """Execute a completion request with retry and basic budget checks."""
        if not user_id.strip():
            raise ValueError("user_id must be a non-empty string.")
        if not prompt.strip():
            raise ValueError("prompt must be a non-empty string.")

        estimated_total_tokens = max(1, len(prompt) // 4) + max(1, max_tokens)
        estimated_cost_cents = self._estimate_cost_cents(estimated_total_tokens)
        if self._budget_limit_cents is not None and estimated_cost_cents > self._budget_limit_cents:
            raise BudgetExceededError(
                "Estimated request cost exceeds configured budget.",
                retry_after_seconds=3600,
            )

        for attempt in range(self._max_retries + 1):
            try:
                response = self._client.chat.completions.create(
                    model=self._model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=max_tokens,
                    temperature=temperature,
                    timeout=self._timeout_seconds,
                )
                usage = getattr(response, "usage", None)
                total_tokens = int(getattr(usage, "total_tokens", estimated_total_tokens))
                cost_cents = self._estimate_cost_cents(total_tokens)
                message = response.choices[0].message.content or ""
                response_id = getattr(response, "id", None)
                return RequestResult(
                    text=message,
                    total_tokens=total_tokens,
                    cost_cents=cost_cents,
                    response_id=response_id,
                )
            except OpenAIError as exc:
                error_text = str(exc).lower()
                if "rate limit" in error_text:
                    if attempt >= self._max_retries:
                        raise DeepSeekRateLimitError(str(exc)) from exc
                    time.sleep(self._base_backoff_seconds * (2**attempt))
                    continue
                raise DeepSeekProviderError(str(exc)) from exc

        raise DeepSeekProviderError("DeepSeek request failed after retries.")

    @staticmethod
    def _estimate_cost_cents(total_tokens: int) -> int:
        """Estimate spend in cents using a conservative token price."""
        # 0.2 cents per 1K tokens (rounded up to at least 1 cent for non-zero requests).
        normalized_tokens = max(0, total_tokens)
        if normalized_tokens == 0:
            return 0
        estimated = (normalized_tokens / 1000.0) * 0.2
        return max(1, int(round(estimated)))
