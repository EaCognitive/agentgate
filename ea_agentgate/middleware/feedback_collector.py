"""Feedback collector middleware for DPO training dataset generation.

Captures guardrail decisions from other middleware and stores them as
feedback records for later use in Direct Preference Optimization (DPO).
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
import uuid
from typing import Any, TYPE_CHECKING

from .base import Middleware, MiddlewareContext
from .input_extraction import extract_prompt_text
from ..feedback.models import FeedbackRecord

if TYPE_CHECKING:
    from ..feedback.storage import FeedbackStorage

logger = logging.getLogger(__name__)


class FeedbackCollector(Middleware):
    """Collects guardrail decisions for DPO dataset generation.

    This middleware runs AFTER other middleware in the chain and
    collects their decisions for later use in training local security
    models via Direct Preference Optimization.

    Example:
        from ea_agentgate import Agent
        from ea_agentgate.middleware.prompt_guard import PromptGuardMiddleware
        from ea_agentgate.middleware.feedback_collector import FeedbackCollector
        from ea_agentgate.feedback.storage import MemoryFeedbackStorage

        storage = MemoryFeedbackStorage()
        agent = Agent(
            name="secure-agent",
            middleware=[
                PromptGuardMiddleware(threshold=0.9),
                FeedbackCollector(storage=storage),
            ],
        )

    Args:
        storage: Backend for storing feedback records
        collect_allowed: Whether to collect allowed prompts
        collect_blocked: Whether to collect blocked prompts
        sample_rate: Sampling rate for high-traffic scenarios (0.0-1.0)
        min_confidence: Only collect decisions above this confidence
    """

    def __init__(
        self,
        storage: FeedbackStorage,
        *,
        collect_allowed: bool = True,
        collect_blocked: bool = True,
        sample_rate: float = 1.0,
        min_confidence: float = 0.0,
    ) -> None:
        super().__init__()
        self.storage = storage
        self.collect_allowed = collect_allowed
        self.collect_blocked = collect_blocked
        self.sample_rate = sample_rate
        self.min_confidence = min_confidence

        if not 0.0 <= sample_rate <= 1.0:
            raise ValueError(f"sample_rate must be in [0, 1], got {sample_rate}")
        if not 0.0 <= min_confidence <= 1.0:
            raise ValueError(f"min_confidence must be in [0, 1], got {min_confidence}")

    @property
    def name(self) -> str:
        """Return the middleware identifier."""
        return "FeedbackCollector"

    def _collect_records(
        self,
        ctx: MiddlewareContext,
        prompt: str,
    ) -> list[FeedbackRecord]:
        """Gather feedback records from all preceding middleware decisions.

        Consolidates guardrail, prompt guard, and semantic validator
        collection into a single pass over known metadata keys.
        """
        collectors: list[tuple[str, str]] = [
            ("guardrail_result", "_collect_guardrail"),
            ("prompt_guard", "_collect_prompt_guard"),
        ]

        records: list[FeedbackRecord] = []
        for metadata_key, method_name in collectors:
            if metadata_key not in ctx.metadata:
                continue
            record = getattr(self, method_name)(ctx, prompt)
            if record:
                records.append(record)

        if "semantic_checks" in ctx.metadata:
            for semantic_record in self._collect_semantic(ctx, prompt):
                if semantic_record:
                    records.append(semantic_record)

        return records

    def after(
        self,
        ctx: MiddlewareContext,
        _result: Any,
        _error: Exception | None,
    ) -> None:
        """Collect feedback from all preceding middleware decisions."""
        if not self._should_sample():
            return

        prompt = self._extract_prompt(ctx.inputs)
        if not prompt:
            return

        records = self._collect_records(ctx, prompt)

        for record in records:
            try:
                self.storage.store(record)
            except (OSError, ValueError) as exc:
                logger.error("Failed to store feedback record: %s", exc, exc_info=False)

    async def aafter(
        self,
        ctx: MiddlewareContext,
        result: Any,
        error: Exception | None,
    ) -> None:
        """Async version of feedback collection."""
        await asyncio.to_thread(self.after, ctx, result, error)

    def _should_sample(self) -> bool:
        """Determine if this request should be sampled."""
        if self.sample_rate >= 1.0:
            return True
        return random.random() < self.sample_rate

    def _extract_prompt(self, inputs: dict[str, Any]) -> str:
        """Extract prompt text from tool inputs."""
        return extract_prompt_text(inputs)

    def _collect_guardrail(
        self,
        ctx: MiddlewareContext,
        prompt: str,
    ) -> FeedbackRecord | None:
        """Collect feedback from StatefulGuardrail middleware."""
        guardrail_data = ctx.metadata.get("guardrail_result", {})
        allowed = guardrail_data.get("allowed", True)
        decision = "allowed" if allowed else "blocked"

        # Apply filters
        if decision == "allowed" and not self.collect_allowed:
            return None
        if decision == "blocked" and not self.collect_blocked:
            return None

        # Confidence is implicitly 1.0 for policy-based guardrails
        confidence = 1.0
        if confidence < self.min_confidence:
            return None

        return FeedbackRecord(
            record_id=str(uuid.uuid4()),
            timestamp=time.time(),
            prompt=prompt,
            decision=decision,
            source="StatefulGuardrail",
            confidence=confidence,
            reason=guardrail_data.get("reason", "No reason provided"),
            threat_type=guardrail_data.get("violated_constraint"),
            model_prediction=None,
            metadata={
                "previous_state": guardrail_data.get("previous_state"),
                "new_state": guardrail_data.get("new_state"),
                "mode": guardrail_data.get("mode"),
                "timestamp": guardrail_data.get("timestamp"),
            },
        )

    def _collect_prompt_guard(
        self,
        ctx: MiddlewareContext,
        prompt: str,
    ) -> FeedbackRecord | None:
        """Collect feedback from PromptGuard middleware."""
        guard_data = ctx.metadata.get("prompt_guard")
        if not guard_data:
            return None

        threat_detected = guard_data.get("threat_detected", False)
        decision = "blocked" if threat_detected else "allowed"

        # Apply filters
        if decision == "allowed" and not self.collect_allowed:
            return None
        if decision == "blocked" and not self.collect_blocked:
            return None

        # Use threat_score as confidence
        confidence = guard_data.get("threat_score", 0.0)
        if confidence < self.min_confidence:
            return None

        threat_type = guard_data.get("threat_type")
        reason = f"{threat_type} detected" if threat_type else "Prompt appears benign"

        return FeedbackRecord(
            record_id=str(uuid.uuid4()),
            timestamp=time.time(),
            prompt=prompt,
            decision=decision,
            source="PromptGuard",
            confidence=confidence,
            reason=reason,
            threat_type=threat_type,
            model_prediction={
                "benign_prob": guard_data.get("benign_prob"),
                "injection_prob": guard_data.get("injection_prob"),
                "jailbreak_prob": guard_data.get("jailbreak_prob"),
                "predicted_label": guard_data.get("predicted_label"),
            },
            metadata={
                "threat_score": guard_data.get("threat_score"),
            },
        )

    def _collect_semantic(
        self,
        ctx: MiddlewareContext,
        prompt: str,
    ) -> list[FeedbackRecord]:
        """Collect feedback from SemanticValidator middleware."""
        semantic_data = ctx.metadata.get("semantic_checks", [])
        records = []

        for check in semantic_data:
            passed = check.get("passed", True)
            decision = "allowed" if passed else "blocked"

            # Apply filters
            if decision == "allowed" and not self.collect_allowed:
                continue
            if decision == "blocked" and not self.collect_blocked:
                continue

            score = check.get("score", 0.0)
            if score < self.min_confidence:
                continue

            check_type = check.get("type", "unknown")
            records.append(
                FeedbackRecord(
                    record_id=str(uuid.uuid4()),
                    timestamp=time.time(),
                    prompt=prompt,
                    decision=decision,
                    source="SemanticValidator",
                    confidence=score,
                    reason=f"Semantic check [{check_type}] result",
                    threat_type=check_type,
                    model_prediction=None,
                    metadata={"check_type": check_type},
                )
            )

        return records


__all__ = [
    "FeedbackCollector",
    "FeedbackRecord",
]
