"""Feedback collection and DPO dataset generation.

This package provides tools for collecting guardrail decisions and
converting them into Direct Preference Optimization (DPO) training
datasets for fine-tuning local security models.

Example:
    from ea_agentgate import Agent
    from ea_agentgate.middleware import PromptGuardMiddleware, FeedbackCollector
    from ea_agentgate.feedback import (
        FeedbackRecord,
        MemoryFeedbackStorage,
        DPOFormatter,
    )

    # Setup feedback collection
    storage = MemoryFeedbackStorage()
    agent = Agent(
        middleware=[
            PromptGuardMiddleware(threshold=0.9),
            FeedbackCollector(storage=storage),
        ]
    )

    # Generate DPO dataset after collecting feedback
    formatter = DPOFormatter(storage, min_confidence=0.7)
    pairs = formatter.generate_dpo_pairs(max_pairs=1000)
    formatter.export_huggingface_dpo(pairs, "train.jsonl")
"""

from .models import FeedbackRecord
from .storage import (
    FeedbackStorage,
    MemoryFeedbackStorage,
    JSONFileFeedbackStorage,
)
from .dpo_formatter import (
    DPOFormatter,
    DPOExample,
)

__all__ = [
    "FeedbackRecord",
    "FeedbackStorage",
    "MemoryFeedbackStorage",
    "JSONFileFeedbackStorage",
    "DPOFormatter",
    "DPOExample",
]
