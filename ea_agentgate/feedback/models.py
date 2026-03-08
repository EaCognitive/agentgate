"""Feedback data models for DPO training dataset generation.

Defines core data structures used throughout the feedback collection
pipeline for guardrail decisions and preference learning.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class FeedbackRecord:
    """A single feedback record from guardrail evaluation.

    Represents a decision made by middleware guardrails, capturing all
    relevant information needed for Direct Preference Optimization (DPO)
    training dataset generation.

    Attributes:
        record_id: Unique identifier for this record
        timestamp: Unix timestamp of when the decision was made
        prompt: The input text that was evaluated
        decision: "allowed" or "blocked"
        source: Name of the middleware that made the decision
        confidence: Confidence score (0.0-1.0)
        reason: Human-readable explanation of the decision
        threat_type: Type of threat detected (if any)
        model_prediction: Raw model output (if available)
        metadata: Additional context and information

    Example:
        record = FeedbackRecord(
            record_id="abc-123",
            timestamp=time.time(),
            prompt="What is the weather?",
            decision="allowed",
            source="PromptGuard",
            confidence=0.95,
            reason="Benign question about weather",
            threat_type=None,
            model_prediction={"benign_prob": 0.95},
            metadata={"user_id": "user123"},
        )
    """

    record_id: str
    timestamp: float
    prompt: str
    decision: str
    source: str
    confidence: float
    reason: str
    threat_type: str | None = None
    model_prediction: dict | None = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization.

        Returns:
            Dictionary representation suitable for JSON serialization
        """
        return {
            "record_id": self.record_id,
            "timestamp": self.timestamp,
            "prompt": self.prompt,
            "decision": self.decision,
            "source": self.source,
            "confidence": self.confidence,
            "reason": self.reason,
            "threat_type": self.threat_type,
            "model_prediction": self.model_prediction,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FeedbackRecord:
        """Create from dictionary.

        Args:
            data: Dictionary containing record fields

        Returns:
            FeedbackRecord instance

        Raises:
            KeyError: If required fields are missing
            ValueError: If field values are invalid
        """
        return cls(
            record_id=data["record_id"],
            timestamp=data["timestamp"],
            prompt=data["prompt"],
            decision=data["decision"],
            source=data["source"],
            confidence=data["confidence"],
            reason=data["reason"],
            threat_type=data.get("threat_type"),
            model_prediction=data.get("model_prediction"),
            metadata=data.get("metadata", {}),
        )


__all__ = [
    "FeedbackRecord",
]
