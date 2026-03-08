"""DPO dataset formatter for feedback records.

Converts collected guardrail feedback into Direct Preference
Optimization (DPO) training datasets compatible with HuggingFace TRL
and OpenAI fine-tuning formats.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TYPE_CHECKING

from .models import FeedbackRecord

if TYPE_CHECKING:
    from .storage import FeedbackStorage

logger = logging.getLogger(__name__)

# Label templates for DPO training
BLOCKED_LABEL = "UNSAFE"
ALLOWED_LABEL = "SAFE"

CLASSIFICATION_SYSTEM_PROMPT = "You are a security classifier. Classify prompts as SAFE or UNSAFE."

CLASSIFICATION_PROMPT_TEMPLATE = "Classify this prompt:\n\n{prompt}\n\nResponse:"


@dataclass
class DPOExample:
    """A single DPO training example.

    DPO (Direct Preference Optimization) trains models to prefer one
    output over another for the same input prompt.

    Attributes:
        prompt: The input text to classify
        chosen: The preferred response/label
        rejected: The non-preferred response/label
        metadata: Additional context for debugging/analysis
    """

    prompt: str
    chosen: str
    rejected: str
    metadata: dict

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "prompt": self.prompt,
            "chosen": self.chosen,
            "rejected": self.rejected,
            "metadata": self.metadata,
        }


class DPOFormatter:
    """Formats feedback records into DPO training datasets.

    Generates training pairs from collected guardrail decisions where:
    - Blocked prompts: chosen=UNSAFE, rejected=SAFE
    - Allowed prompts: chosen=SAFE, rejected=UNSAFE

    Example:
        from ea_agentgate.feedback.storage import JSONFileFeedbackStorage
        from ea_agentgate.feedback.dpo_formatter import DPOFormatter

        storage = JSONFileFeedbackStorage("feedback.jsonl")
        formatter = DPOFormatter(storage, min_confidence=0.7)

        pairs = formatter.generate_dpo_pairs(max_pairs=1000)
        stats = formatter.export_huggingface_dpo(pairs, "train.jsonl")
    """

    def __init__(
        self,
        storage: FeedbackStorage,
        min_confidence: float = 0.7,
    ) -> None:
        """Initialize DPO formatter.

        Args:
            storage: Feedback storage backend
            min_confidence: Only use decisions above this confidence
        """
        self.storage = storage
        self.min_confidence = min_confidence

        if not 0.0 <= min_confidence <= 1.0:
            raise ValueError(f"min_confidence must be in [0, 1], got {min_confidence}")

    def generate_dpo_pairs(
        self,
        since: float | None = None,
        max_pairs: int = 10000,
    ) -> list[DPOExample]:
        """Generate DPO training pairs from feedback records.

        Strategy:
        1. Query high-confidence feedback records
        2. Create preference pairs where:
           - Blocked prompts: prefer UNSAFE label over SAFE
           - Allowed prompts: prefer SAFE label over UNSAFE
        3. Include metadata for debugging and analysis

        Args:
            since: Only use records after this timestamp
            max_pairs: Maximum number of pairs to generate

        Returns:
            List of DPO training examples
        """
        # Query records above confidence threshold
        all_records = self.storage.query(since=since, limit=max_pairs * 2)

        # Filter by confidence
        high_conf_records = [r for r in all_records if r.confidence >= self.min_confidence]

        logger.info(
            "Generating DPO pairs from %d high-confidence records (min_confidence=%.2f)",
            len(high_conf_records),
            self.min_confidence,
        )

        pairs: list[DPOExample] = []

        for record in high_conf_records:
            if len(pairs) >= max_pairs:
                break

            pair = self._create_dpo_pair(record)
            if pair:
                pairs.append(pair)

        logger.info("Generated %d DPO training pairs", len(pairs))
        return pairs

    def _create_dpo_pair(self, record: FeedbackRecord) -> DPOExample | None:
        """Create a DPO pair from a feedback record.

        Args:
            record: Feedback record to convert

        Returns:
            DPO example or None if record cannot be converted
        """
        if not record.prompt.strip():
            return None

        # Format the classification prompt
        classification_input = CLASSIFICATION_PROMPT_TEMPLATE.format(prompt=record.prompt)

        # Create preference pair based on decision
        if record.decision == "blocked":
            # Model should prefer UNSAFE label for blocked prompts
            chosen = self._format_response(BLOCKED_LABEL, record.reason, record.threat_type)
            rejected = self._format_response(ALLOWED_LABEL, "This prompt appears safe", None)
        elif record.decision == "allowed":
            # Model should prefer SAFE label for allowed prompts
            chosen = self._format_response(ALLOWED_LABEL, "This prompt appears safe", None)
            rejected = self._format_response(BLOCKED_LABEL, record.reason, record.threat_type)
        else:
            logger.warning(
                "Unknown decision type: %s (record_id=%s)", record.decision, record.record_id
            )
            return None

        return DPOExample(
            prompt=classification_input,
            chosen=chosen,
            rejected=rejected,
            metadata={
                "record_id": record.record_id,
                "source": record.source,
                "confidence": record.confidence,
                "decision": record.decision,
                "threat_type": record.threat_type,
                "timestamp": record.timestamp,
            },
        )

    def _format_response(
        self,
        label: str,
        reason: str,
        threat_type: str | None,
    ) -> str:
        """Format a classification response.

        Args:
            label: SAFE or UNSAFE
            reason: Explanation for the classification
            threat_type: Type of threat (if unsafe)

        Returns:
            Formatted response string
        """
        if threat_type:
            return f"{label}: {threat_type} - {reason}"
        return f"{label}: {reason}"

    def export_huggingface_dpo(
        self,
        pairs: list[DPOExample],
        output_path: str | Path,
    ) -> dict[str, Any]:
        """Export in HuggingFace DPO format (JSONL).

        Format per line:
        {
            "prompt": "Classify this text as safe or unsafe: {text}",
            "chosen": "SAFE: This is a benign request...",
            "rejected": "UNSAFE: This contains injection...",
            "metadata": {...}
        }

        Compatible with HuggingFace TRL DPOTrainer.

        Args:
            pairs: List of DPO examples
            output_path: Path to write JSONL file

        Returns:
            Dictionary with export statistics
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                for pair in pairs:
                    json.dump(pair.to_dict(), f, ensure_ascii=False)
                    f.write("\n")

            stats = {
                "format": "huggingface_dpo",
                "output_path": str(output_path),
                "total_examples": len(pairs),
                "file_size_bytes": output_path.stat().st_size,
            }

            logger.info(
                "Exported %d examples to HuggingFace DPO format: %s", len(pairs), output_path
            )

            return stats

        except (OSError, ValueError) as exc:
            logger.error("Failed to export DPO dataset: %s", exc)
            raise OSError(f"Failed to export DPO dataset: {exc}") from exc

    def export_openai_preference(
        self,
        pairs: list[DPOExample],
        output_path: str | Path,
    ) -> dict[str, Any]:
        """Export in OpenAI preference format.

        Format per line:
        {
            "input": [
                {"role": "system", "content": "..."},
                {"role": "user", "content": "..."}
            ],
            "preferred_output": "...",
            "non_preferred_output": "..."
        }

        Args:
            pairs: List of DPO examples
            output_path: Path to write JSONL file

        Returns:
            Dictionary with export statistics
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                for pair in pairs:
                    openai_format = {
                        "input": [
                            {"role": "system", "content": CLASSIFICATION_SYSTEM_PROMPT},
                            {"role": "user", "content": pair.prompt},
                        ],
                        "preferred_output": pair.chosen,
                        "non_preferred_output": pair.rejected,
                    }
                    json.dump(openai_format, f, ensure_ascii=False)
                    f.write("\n")

            stats = {
                "format": "openai_preference",
                "output_path": str(output_path),
                "total_examples": len(pairs),
                "file_size_bytes": output_path.stat().st_size,
            }

            logger.info(
                "Exported %d examples to OpenAI preference format: %s", len(pairs), output_path
            )

            return stats

        except (OSError, ValueError) as exc:
            logger.error("Failed to export OpenAI dataset: %s", exc)
            raise OSError(f"Failed to export OpenAI dataset: {exc}") from exc

    def get_statistics(self) -> dict[str, Any]:
        """Return stats about collected feedback for monitoring.

        Returns:
            Dictionary with feedback statistics
        """
        counts = self.storage.count()

        # Calculate high-confidence records
        all_records = self.storage.query(limit=1000000)
        high_conf = sum(1 for r in all_records if r.confidence >= self.min_confidence)

        # Count by threat type
        threat_counts: dict[str, int] = {}
        for record in all_records:
            if record.threat_type:
                threat_counts[record.threat_type] = threat_counts.get(record.threat_type, 0) + 1

        return {
            "total_records": counts["total"],
            "allowed_records": counts["allowed"],
            "blocked_records": counts["blocked"],
            "high_confidence_records": high_conf,
            "min_confidence_threshold": self.min_confidence,
            "threat_type_distribution": threat_counts,
            "sources": {k: v for k, v in counts.items() if k.startswith("source_")},
        }


__all__ = [
    "DPOFormatter",
    "DPOExample",
]
