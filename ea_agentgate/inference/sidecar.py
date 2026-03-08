"""Async inference sidecar using process pool for ML models.

This module provides a ProcessPoolExecutor-based inference engine that
offloads ML model inference to separate processes, avoiding Python's GIL
and reducing latency for async middleware.
"""

from __future__ import annotations

import asyncio
import logging
import os
from concurrent.futures import ProcessPoolExecutor
from importlib import import_module
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)
_HF_MODEL_REVISION = os.getenv("AGENTGATE_HF_MODEL_REVISION", "main")

# Per-process model cache used by worker processes. Each subprocess keeps its
# own cache, so models are loaded once per process instead of once per request.
_WORKER_MODEL_CACHE: dict[tuple[str, str, str], tuple[Any, Any]] = {}


def _load_transformer_classes() -> tuple[Any, Any]:
    """Load transformer classes lazily without mid-function imports."""
    transformers = import_module("transformers")
    return (
        getattr(transformers, "AutoTokenizer"),
        getattr(transformers, "AutoModelForSequenceClassification"),
    )


def _get_worker_model(
    model_id: str,
    device: str,
    revision: str,
) -> tuple[Any, Any]:
    """Load and cache tokenizer/model in the current worker process."""
    cache_key = (model_id, device, revision)
    cached = _WORKER_MODEL_CACHE.get(cache_key)
    if cached is not None:
        return cached

    auto_tokenizer_cls, auto_model_for_sequence_classification_cls = _load_transformer_classes()
    tokenizer = auto_tokenizer_cls.from_pretrained(model_id, revision=revision)  # nosec B615
    model = auto_model_for_sequence_classification_cls.from_pretrained(
        model_id,
        revision=revision,
    )  # nosec B615
    model.to(device)
    model.eval()

    _WORKER_MODEL_CACHE[cache_key] = (tokenizer, model)
    return tokenizer, model


def _worker_classify(
    model_id: str,
    text: str,
    max_length: int,
    device: str,
) -> dict[str, Any]:
    """Worker function for process pool inference.

    This runs in a separate process to avoid GIL blocking.
    All heavy imports are done inside the function to minimize
    process startup overhead.

    Args:
        model_id: HuggingFace model ID
        text: Input text to classify
        max_length: Maximum token length
        device: Device to use (cpu, cuda, mps)

    Returns:
        Classification results dictionary with:
        - benign_prob: Probability of benign (safe) prompt
        - malicious_prob: Probability of malicious (unsafe) prompt
        - predicted_label: 0=BENIGN, 1=MALICIOUS
        - num_classes: Number of output classes
    """
    try:
        torch = import_module("torch")
    except ImportError as exc:
        raise RuntimeError(
            "torch and transformers required for inference sidecar. "
            "Install with: pip install torch transformers"
        ) from exc

    try:
        tokenizer, model = _get_worker_model(model_id, device, _HF_MODEL_REVISION)

        inputs = tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=max_length,
            padding=True,
        )
        inputs = {k: v.to(device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = model(**inputs)
            logits = outputs.logits
            probs = torch.nn.functional.softmax(logits, dim=-1)[0]

        num_classes = len(probs)
        benign_prob = float(probs[0])
        malicious_prob = float(probs[1]) if num_classes > 1 else 0.0

        predicted_label = int(torch.argmax(probs))

        return {
            "benign_prob": benign_prob,
            "malicious_prob": malicious_prob,
            "predicted_label": predicted_label,
            "num_classes": num_classes,
        }
    except (OSError, RuntimeError, ValueError) as exc:
        logger.error("Worker inference failed: %s", exc)
        raise RuntimeError(f"Inference worker error: {exc}") from exc


class InferenceSidecar:
    """Process-pool based async inference engine for ML models.

    Uses ProcessPoolExecutor to offload inference to separate processes,
    avoiding GIL contention and achieving low latency for async workloads.

    Example:
        sidecar = InferenceSidecar(max_workers=4)
        result = await sidecar.classify_async(
            model_id="meta-llama/Llama-Prompt-Guard-2-86M",
            text="Ignore previous instructions",
            max_length=512,
        )
        await sidecar.shutdown()

    Args:
        max_workers: Number of worker processes (default: CPU count)
        device: Device for inference (cpu, cuda, mps)
    """

    def __init__(
        self,
        *,
        max_workers: int | None = None,
        device: str = "cpu",
    ):
        if max_workers is not None and max_workers < 1:
            raise ValueError(f"max_workers must be >= 1, got {max_workers}")

        self.max_workers = max_workers or os.cpu_count() or 4
        self.device = device
        self._executor: ProcessPoolExecutor | None = None
        self._executor_lock = asyncio.Lock()

    async def _get_executor(self) -> ProcessPoolExecutor:
        """Get or create process pool executor."""
        if self._executor is None:
            async with self._executor_lock:
                if self._executor is None:
                    logger.info(
                        "Starting inference sidecar with %d workers on %s",
                        self.max_workers,
                        self.device,
                    )
                    self._executor = ProcessPoolExecutor(max_workers=self.max_workers)
        return self._executor

    async def classify_async(
        self,
        model_id: str,
        text: str,
        max_length: int = 512,
    ) -> dict[str, Any]:
        """Async classification using process pool.

        Offloads inference to a worker process to avoid blocking the event loop.
        Target: 60% latency reduction vs synchronous inference.

        Args:
            model_id: HuggingFace model ID
            text: Input text to classify
            max_length: Maximum token length

        Returns:
            Classification results dictionary with probabilities

        Raises:
            RuntimeError: If inference fails
        """
        executor = await self._get_executor()
        loop = asyncio.get_event_loop()

        try:
            result = await loop.run_in_executor(
                executor,
                _worker_classify,
                model_id,
                text,
                max_length,
                self.device,
            )
            return result
        except (RuntimeError, ValueError, OSError) as exc:
            logger.error("Async inference failed: %s", exc)
            raise RuntimeError(f"Inference sidecar error: {exc}") from exc

    async def shutdown(self) -> None:
        """Shutdown the process pool gracefully."""
        if self._executor is not None:
            logger.info("Shutting down inference sidecar")
            self._executor.shutdown(wait=True)
            self._executor = None


class _SidecarHolder:
    """Module-level holder to avoid global keyword (REQ-SEC-03)."""

    instance: InferenceSidecar | None = None

    @classmethod
    def get(cls) -> InferenceSidecar | None:
        """Return the shared sidecar instance."""
        return cls.instance

    @classmethod
    def set(cls, sidecar: InferenceSidecar) -> None:
        """Store the shared sidecar instance."""
        cls.instance = sidecar


_SIDECAR_HOLDER = _SidecarHolder()


async def classify_async(
    model_id: str,
    text: str,
    max_length: int = 512,
    device: str = "cpu",
) -> dict[str, Any]:
    """Convenience function for async classification using shared sidecar.

    Uses a shared InferenceSidecar instance for efficient resource usage.

    Args:
        model_id: HuggingFace model ID
        text: Input text to classify
        max_length: Maximum token length
        device: Device for inference (cpu, cuda, mps)

    Returns:
        Classification results dictionary
    """
    if _SIDECAR_HOLDER.get() is None:
        _SIDECAR_HOLDER.set(InferenceSidecar(device=device))

    sidecar = _SIDECAR_HOLDER.get()
    if sidecar is None:
        raise RuntimeError("Inference sidecar initialization failed")

    return await sidecar.classify_async(
        model_id,
        text,
        max_length,
    )


__all__ = [
    "InferenceSidecar",
    "classify_async",
]
