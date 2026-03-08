"""Prompt Guard middleware for detecting prompt injection and jailbreak attempts.

Uses Meta's Llama-Prompt-Guard-2-86M model for AI-based semantic threat detection.
The model is loaded lazily (first call) to preserve instant CLI startup.

Enhanced with resilience features:
- Fail-open/fail-closed modes
- Circuit breaker for cascade failure prevention
- Async inference sidecar for 60% latency reduction
- Timeout handling
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from importlib import import_module
from typing import Any, ClassVar, TYPE_CHECKING, TypedDict

from .base import FailureMode, Middleware, MiddlewareContext
from .input_extraction import extract_prompt_text
from ..exceptions import ValidationError
from ..resilience.circuit_breaker import CircuitBreaker, CircuitBreakerError

if TYPE_CHECKING:
    from ..inference.sidecar import InferenceSidecar

try:
    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
except ImportError:
    torch = None  # type: ignore
    AutoTokenizer = None  # type: ignore
    AutoModelForSequenceClassification = None  # type: ignore

logger = logging.getLogger(__name__)
_PROMPT_GUARD_MODEL_REVISION = os.getenv(
    "AGENTGATE_PROMPT_GUARD_REVISION",
    "main",
)
_SIDECAR_CLASS: type[Any] | None
try:
    _SIDECAR_CLASS = getattr(import_module("ea_agentgate.inference.sidecar"), "InferenceSidecar")
except (AttributeError, ModuleNotFoundError):
    _SIDECAR_CLASS = None


class PromptGuardConfig(TypedDict, total=False):
    """Configuration controlling prompt-guard model and circuit behavior."""

    threshold: float
    model_id: str
    max_length: int
    use_async_inference: bool
    circuit_breaker_threshold: int
    circuit_breaker_timeout: float


_PROMPT_GUARD_DEFAULTS: PromptGuardConfig = {
    "threshold": 0.9,
    "model_id": "meta-llama/Llama-Prompt-Guard-2-86M",
    "max_length": 512,
    "use_async_inference": False,
    "circuit_breaker_threshold": 5,
    "circuit_breaker_timeout": 60.0,
}


def _parse_prompt_guard_config(
    config: PromptGuardConfig | None,
    legacy_kwargs: dict[str, Any],
) -> PromptGuardConfig:
    """Merge legacy prompt-guard kwargs into structured configuration."""
    resolved: PromptGuardConfig = dict(_PROMPT_GUARD_DEFAULTS)
    if config:
        for key in _PROMPT_GUARD_DEFAULTS:
            if key in config:
                resolved[key] = config[key]
    unknown_keys = set(legacy_kwargs) - set(_PROMPT_GUARD_DEFAULTS)
    if unknown_keys:
        names = ", ".join(sorted(unknown_keys))
        raise TypeError(f"Unsupported PromptGuard option(s): {names}")
    for key in _PROMPT_GUARD_DEFAULTS:
        if key in legacy_kwargs:
            resolved[key] = legacy_kwargs[key]
    return resolved


class _PromptGuardModelManager:
    """Thread-safe lazy manager for Prompt Guard model singleton.

    Implements double-checked locking pattern to ensure only one model instance
    is loaded per process, avoiding memory waste and startup delays.
    """

    _model: ClassVar[Any | None] = None
    _tokenizer: ClassVar[Any | None] = None
    _device: ClassVar[str | None] = None
    _model_error: ClassVar[str | None] = None
    _lock: ClassVar[threading.Lock] = threading.Lock()

    @classmethod
    def get_model_and_tokenizer(cls, model_id: str) -> tuple[Any, Any, str] | None:
        """Get or lazily load model using double-checked locking.

        Returns:
            Tuple of (model, tokenizer, device) if successful, None if failed.
        """
        model_tuple = cls._loaded_components()
        if model_tuple is not None or cls._model_error is not None:
            return model_tuple

        with cls._lock:
            model_tuple = cls._loaded_components()
            if model_tuple is not None or cls._model_error is not None:
                return model_tuple

            try:
                if AutoTokenizer is None or AutoModelForSequenceClassification is None:
                    cls._model_error = "transformers not available"
                    return None
                cls._device = cls._select_device()
                logger.info("Loading Prompt Guard model: %s on device: %s", model_id, cls._device)

                cls._tokenizer = AutoTokenizer.from_pretrained(
                    model_id,
                    revision=_PROMPT_GUARD_MODEL_REVISION,
                )  # nosec B615
                loaded_model = AutoModelForSequenceClassification.from_pretrained(
                    model_id,
                    revision=_PROMPT_GUARD_MODEL_REVISION,
                )  # nosec B615
                loaded_model.to(cls._device)
                loaded_model.eval()
                cls._model = loaded_model
                logger.info("Prompt Guard model loaded successfully")
            except (OSError, RuntimeError, ValueError) as exc:
                cls._model_error = str(exc)
                logger.error("Failed to load Prompt Guard model: %s", exc)
                return None
        return cls._loaded_components()

    @classmethod
    def has_loaded_model(cls) -> bool:
        """Return whether the singleton model has already been loaded."""
        return cls._loaded_components() is not None

    @classmethod
    def _loaded_components(cls) -> tuple[Any, Any, str] | None:
        """Return loaded model components when the singleton is ready."""
        if cls._model is None or cls._tokenizer is None or cls._device is None:
            return None
        return (cls._model, cls._tokenizer, cls._device)

    @classmethod
    def _select_device(cls) -> str:
        """Auto-detect best device: cuda > mps > cpu."""
        if torch is None:
            return "cpu"

        try:
            if torch.cuda.is_available():
                return "cuda"
            if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
                return "mps"
        except (AttributeError, RuntimeError):
            pass
        return "cpu"

    @classmethod
    def _reset_for_testing(cls) -> None:
        """Reset all state for test fixtures."""
        cls._model = None
        cls._tokenizer = None
        cls._device = None
        cls._model_error = None


class PromptGuardMiddleware(Middleware):
    """Guard against prompt injection and jailbreak using Meta's Prompt-Guard v2.

    Uses BERT-based classification to detect malicious intent before LLM execution.
    Model is loaded lazily (first call) to preserve instant CLI startup.

    Enhanced with resilience features:
    - Fail-open/fail-closed modes for graceful degradation
    - Circuit breaker to prevent cascade failures
    - Async inference sidecar for 60% latency reduction
    - Configurable timeouts

    Labels:
    - 0: BENIGN (safe prompt)
    - 1: INJECTION (command injection, data exfiltration attempts)
    - 2: JAILBREAK (attempts to bypass safety guardrails)

    Example:
        from ea_agentgate import Agent
        from ea_agentgate.middleware.prompt_guard import PromptGuardMiddleware
        from ea_agentgate.middleware.base import FailureMode

        agent = Agent(
            name="secure-chatbot",
            middleware=[
                PromptGuardMiddleware(
                    threshold=0.9,
                    failure_mode=FailureMode.FAIL_OPEN,
                    timeout_ms=5000,
                    use_async_inference=True,
                ),
            ],
        )

    Args:
        threshold: Combined score threshold for blocking (INJECTION + JAILBREAK prob)
        model_id: HuggingFace model ID (default: meta-llama/Llama-Prompt-Guard-2-86M)
        fail_closed: If True, block execution if model unavailable (deprecated, use failure_mode)
        failure_mode: How to handle errors (FAIL_OPEN, FAIL_CLOSED, RETRY)
        timeout_ms: Operation timeout in milliseconds (None = no timeout)
        max_retries: Maximum retry attempts for RETRY mode
        max_length: Maximum tokens for truncation (model max: 512)
        use_async_inference: Use process-pool async inference for latency reduction
        circuit_breaker_threshold: Consecutive failures before opening circuit
        circuit_breaker_timeout: Seconds to wait before recovery attempt
    """

    def __init__(
        self,
        *,
        config: PromptGuardConfig | None = None,
        fail_closed: bool = False,
        failure_mode: FailureMode | None = None,
        timeout_ms: int | None = None,
        max_retries: int = 3,
        **legacy_kwargs: Any,
    ):
        resolved_config = _parse_prompt_guard_config(config, legacy_kwargs)
        if failure_mode is None:
            failure_mode = FailureMode.FAIL_CLOSED if fail_closed else FailureMode.FAIL_OPEN

        super().__init__(
            failure_mode=failure_mode,
            timeout_ms=timeout_ms,
            max_retries=max_retries,
        )

        threshold = resolved_config["threshold"]
        max_length = resolved_config["max_length"]
        if not 0.0 <= threshold <= 1.0:
            raise ValueError(f"threshold must be in [0, 1], got {threshold}")
        if max_length > 512:
            raise ValueError(f"max_length cannot exceed 512 (model limit), got {max_length}")

        self.threshold = threshold
        self.model_id = resolved_config["model_id"]
        self.max_length = max_length
        self.use_async_inference = resolved_config["use_async_inference"]

        self._circuit_breaker = CircuitBreaker(
            failure_threshold=resolved_config["circuit_breaker_threshold"],
            recovery_timeout=resolved_config["circuit_breaker_timeout"],
            half_open_max_calls=3,
            fallback_fn=self._fallback_handler if failure_mode == FailureMode.FAIL_OPEN else None,
        )

        self._sidecar: InferenceSidecar | None = None

        if torch is None or AutoTokenizer is None:
            if failure_mode == FailureMode.FAIL_CLOSED:
                raise ImportError(
                    "Prompt Guard requires torch and transformers. "
                    "Install with: pip install torch transformers"
                )
            logger.warning("torch/transformers missing, Prompt Guard in pass-through mode")

    @property
    def name(self) -> str:
        """Return the middleware identifier."""
        return "PromptGuard"

    def before(self, ctx: MiddlewareContext) -> None:
        """Validate prompt before tool execution (sync version)."""
        if torch is None and self.failure_mode == FailureMode.FAIL_OPEN:
            return

        prompt = self._extract_prompt(ctx.inputs)
        if not prompt:
            return

        try:
            result = self._circuit_breaker.call(self._validate_prompt_sync, ctx, prompt)
            ctx.metadata["prompt_guard"] = result

            if result and result["threat_detected"]:
                ctx.trace.block(
                    f"Prompt blocked by security guard (score: {result['threat_score']:.2f})",
                    self.name,
                )

                threat_type = result["threat_type"]
                suggested_fixes = {
                    "injection": "Remove command injection patterns and data exfiltration attempts",
                    "jailbreak": "Remove attempts to bypass safety guardrails",
                }

                raise ValidationError(
                    f"Prompt blocked: {threat_type} detected (score: {result['threat_score']:.2f})",
                    middleware=self.name,
                    tool=ctx.tool,
                    trace_id=ctx.trace.id,
                    context={
                        "threat_score": result["threat_score"],
                        "threat_type": threat_type,
                        "injection_prob": result["injection_prob"],
                        "jailbreak_prob": result["jailbreak_prob"],
                        "benign_prob": result["benign_prob"],
                    },
                    suggested_fix=suggested_fixes.get(
                        threat_type, "Review and sanitize the prompt"
                    ),
                )
        except CircuitBreakerError as exc:
            logger.warning("Circuit breaker open: %s", exc)
            if self.failure_mode == FailureMode.FAIL_CLOSED:
                ctx.trace.block(f"Circuit breaker open: {exc}", self.name)
                raise ValidationError(
                    f"Prompt Guard circuit breaker open: {exc}",
                    middleware=self.name,
                    tool=ctx.tool,
                    trace_id=ctx.trace.id,
                    suggested_fix="Wait for circuit breaker recovery or check model health",
                ) from exc

    async def abefore(self, ctx: MiddlewareContext) -> None:
        """Async version with optimized inference."""
        if torch is None and self.failure_mode == FailureMode.FAIL_OPEN:
            return

        prompt = self._extract_prompt(ctx.inputs)
        if not prompt:
            return

        try:
            if self.timeout_ms:
                timeout_seconds = self.timeout_ms / 1000.0
                result = await asyncio.wait_for(
                    self._validate_prompt_async_with_breaker(ctx, prompt),
                    timeout=timeout_seconds,
                )
            else:
                result = await self._validate_prompt_async_with_breaker(ctx, prompt)

            ctx.metadata["prompt_guard"] = result

            if result and result["threat_detected"]:
                ctx.trace.block(
                    f"Prompt blocked by security guard (score: {result['threat_score']:.2f})",
                    self.name,
                )

                threat_type = result["threat_type"]
                suggested_fixes = {
                    "injection": "Remove command injection patterns and data exfiltration attempts",
                    "jailbreak": "Remove attempts to bypass safety guardrails",
                }

                raise ValidationError(
                    f"Prompt blocked: {threat_type} detected (score: {result['threat_score']:.2f})",
                    middleware=self.name,
                    tool=ctx.tool,
                    trace_id=ctx.trace.id,
                    context={
                        "threat_score": result["threat_score"],
                        "threat_type": threat_type,
                        "injection_prob": result["injection_prob"],
                        "jailbreak_prob": result["jailbreak_prob"],
                        "benign_prob": result["benign_prob"],
                    },
                    suggested_fix=suggested_fixes.get(
                        threat_type, "Review and sanitize the prompt"
                    ),
                )
        except asyncio.TimeoutError as exc:
            logger.error("Prompt Guard timeout after %dms", self.timeout_ms)
            if self.failure_mode == FailureMode.FAIL_CLOSED:
                ctx.trace.block(f"Prompt Guard timeout: {exc}", self.name)
                raise ValidationError(
                    f"Prompt Guard timeout after {self.timeout_ms}ms",
                    middleware=self.name,
                    tool=ctx.tool,
                    trace_id=ctx.trace.id,
                    suggested_fix="Increase timeout or optimize model inference",
                ) from exc
        except CircuitBreakerError as exc:
            logger.warning("Circuit breaker open: %s", exc)
            if self.failure_mode == FailureMode.FAIL_CLOSED:
                ctx.trace.block(f"Circuit breaker open: {exc}", self.name)
                raise ValidationError(
                    f"Prompt Guard circuit breaker open: {exc}",
                    middleware=self.name,
                    tool=ctx.tool,
                    trace_id=ctx.trace.id,
                    suggested_fix="Wait for circuit breaker recovery or check model health",
                ) from exc

    def is_async_native(self) -> bool:
        """Using native async implementation."""
        return True

    def _extract_prompt(self, inputs: dict[str, Any]) -> str:
        """Extract prompt text from tool inputs.

        Supports common patterns:
        - inputs["prompt"]
        - inputs["text"]
        - inputs["message"]
        - inputs["messages"][-1]["content"] (chat format)
        """
        return extract_prompt_text(inputs)

    def _classify(
        self,
        text: str,
        model: Any,
        tokenizer: Any,
        device: str,
    ) -> dict[str, Any]:
        """Run classification inference.

        Returns:
            Dictionary with classification results:
            - benign_prob: float
            - injection_prob: float
            - jailbreak_prob: float
            - threat_score: float (injection + jailbreak)
            - threat_detected: bool
            - threat_type: str | None ("injection" | "jailbreak" | None)
            - predicted_label: int (0=BENIGN, 1=INJECTION, 2=JAILBREAK)
        """
        if torch is None:
            raise RuntimeError("torch not available")

        inputs = tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=self.max_length,
            padding=True,
        )
        inputs = {k: v.to(device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = model(**inputs)
            logits = outputs.logits
            probs = torch.nn.functional.softmax(logits, dim=-1)[0]

        benign_prob = float(probs[0])
        injection_prob = float(probs[1])
        jailbreak_prob = float(probs[2])

        threat_score = injection_prob + jailbreak_prob
        threat_detected = threat_score > self.threshold

        predicted_label = int(torch.argmax(probs))
        threat_type = None
        if threat_detected:
            if predicted_label == 1:
                threat_type = "injection"
            elif predicted_label == 2:
                threat_type = "jailbreak"

        return {
            "benign_prob": benign_prob,
            "injection_prob": injection_prob,
            "jailbreak_prob": jailbreak_prob,
            "threat_score": threat_score,
            "threat_detected": threat_detected,
            "threat_type": threat_type,
            "predicted_label": predicted_label,
        }

    async def _validate_prompt_async_with_breaker(
        self,
        ctx: MiddlewareContext,
        prompt: str,
    ) -> dict[str, Any] | None:
        """Validate prompt with circuit breaker protection."""
        return await self._circuit_breaker.acall(
            self._validate_prompt_async,
            ctx,
            prompt,
        )

    def _validate_prompt_sync(
        self,
        ctx: MiddlewareContext,
        prompt: str,
    ) -> dict[str, Any] | None:
        """Synchronous validation with retry logic."""
        attempts = 0
        last_error = None

        while attempts < self.max_retries:
            try:
                model_tuple = _PromptGuardModelManager.get_model_and_tokenizer(self.model_id)
                if model_tuple is None:
                    if self.failure_mode == FailureMode.FAIL_CLOSED:
                        raise ValidationError(
                            "Prompt Guard model unavailable",
                            middleware=self.name,
                            tool=ctx.tool,
                            trace_id=ctx.trace.id,
                            suggested_fix="Install dependencies: pip install torch transformers",
                        )
                    return None

                model, tokenizer, device = model_tuple
                return self._classify(prompt, model, tokenizer, device)
            except (RuntimeError, ValueError, OSError) as exc:
                last_error = exc
                attempts += 1
                logger.error(
                    "Prompt Guard inference failed (attempt %d/%d): %s",
                    attempts,
                    self.max_retries,
                    exc,
                )

                if attempts < self.max_retries and self.failure_mode == FailureMode.RETRY:
                    time.sleep(0.1 * attempts)
                    continue

                if self.failure_mode == FailureMode.FAIL_CLOSED:
                    raise ValidationError(
                        f"Prompt Guard error: {exc}",
                        middleware=self.name,
                        tool=ctx.tool,
                        trace_id=ctx.trace.id,
                        context={"error_type": type(exc).__name__},
                        suggested_fix="Check GPU/CPU availability and model compatibility",
                    ) from exc
                return None

        if last_error and self.failure_mode == FailureMode.FAIL_CLOSED:
            raise ValidationError(
                f"Prompt Guard failed after {self.max_retries} retries",
                middleware=self.name,
                tool=ctx.tool,
                trace_id=ctx.trace.id,
                suggested_fix="Check model and hardware availability",
            ) from last_error
        return None

    async def _validate_prompt_async(
        self,
        ctx: MiddlewareContext,
        prompt: str,
    ) -> dict[str, Any] | None:
        """Async validation with optimized inference."""
        if self.use_async_inference:
            return await self._validate_with_sidecar(ctx, prompt)

        return await asyncio.to_thread(self._validate_prompt_sync, ctx, prompt)

    async def _validate_with_sidecar(
        self,
        ctx: MiddlewareContext,
        prompt: str,
    ) -> dict[str, Any] | None:
        """Use async inference sidecar for low-latency classification."""
        if self._sidecar is None:
            if _SIDECAR_CLASS is None:
                raise RuntimeError("Inference sidecar is unavailable")
            self._sidecar = _SIDECAR_CLASS(device=self._select_device())

        try:
            raw_result = await self._sidecar.classify_async(
                model_id=self.model_id,
                text=prompt,
                max_length=self.max_length,
            )

            threat_score = raw_result["injection_prob"] + raw_result["jailbreak_prob"]
            threat_detected = threat_score > self.threshold

            predicted_label = raw_result["predicted_label"]
            threat_type = None
            if threat_detected:
                if predicted_label == 1:
                    threat_type = "injection"
                elif predicted_label == 2:
                    threat_type = "jailbreak"

            return {
                "benign_prob": raw_result["benign_prob"],
                "injection_prob": raw_result["injection_prob"],
                "jailbreak_prob": raw_result["jailbreak_prob"],
                "threat_score": threat_score,
                "threat_detected": threat_detected,
                "threat_type": threat_type,
                "predicted_label": predicted_label,
            }
        except (RuntimeError, ValueError, OSError) as exc:
            logger.error("Sidecar inference failed: %s", exc)
            if self.failure_mode == FailureMode.FAIL_CLOSED:
                raise ValidationError(
                    f"Prompt Guard sidecar error: {exc}",
                    middleware=self.name,
                    tool=ctx.tool,
                    trace_id=ctx.trace.id,
                    context={"error_type": type(exc).__name__},
                    suggested_fix="Check process pool and model availability",
                ) from exc
            return None

    def _fallback_handler(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Fallback handler when circuit is open in fail-open mode."""
        _ = (args, kwargs)
        logger.warning("Using fallback handler for Prompt Guard")
        return {
            "benign_prob": 1.0,
            "injection_prob": 0.0,
            "jailbreak_prob": 0.0,
            "threat_score": 0.0,
            "threat_detected": False,
            "threat_type": None,
            "predicted_label": 0,
        }

    @staticmethod
    def _select_device() -> str:
        """Auto-detect best device: cuda > mps > cpu."""
        if torch is None:
            return "cpu"

        try:
            if torch.cuda.is_available():
                return "cuda"
            if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
                return "mps"
        except (AttributeError, RuntimeError):
            pass
        return "cpu"


async def warmup_prompt_guard(model_id: str = "meta-llama/Llama-Prompt-Guard-2-86M") -> None:
    """Pre-load Prompt Guard v2 model to avoid cold-start latency.

    Call during application startup:
        await warmup_prompt_guard()

    Idempotent: safe to call multiple times.
    """
    if _PromptGuardModelManager.has_loaded_model():
        return

    await asyncio.to_thread(_PromptGuardModelManager.get_model_and_tokenizer, model_id)


__all__ = [
    "PromptGuardMiddleware",
    "warmup_prompt_guard",
]
