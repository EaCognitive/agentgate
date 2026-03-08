"""Storage backends for feedback records.

Provides in-memory and file-based storage for collecting guardrail
feedback records used in DPO training dataset generation.
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Protocol

from .models import FeedbackRecord

logger = logging.getLogger(__name__)


class FeedbackStorage(Protocol):
    """Protocol for feedback storage backends."""

    def store(self, record: FeedbackRecord) -> None:
        """Store a feedback record."""
        raise NotImplementedError

    def query(
        self,
        decision: str | None = None,
        source: str | None = None,
        since: float | None = None,
        limit: int = 1000,
    ) -> list["FeedbackRecord"]:
        """Query feedback records with filters."""
        raise NotImplementedError

    def count(self) -> dict[str, int]:
        """Get counts of records by decision and source."""
        raise NotImplementedError


class MemoryFeedbackStorage:
    """In-memory storage for development and testing.

    Thread-safe implementation using RLock for concurrent access.
    Records are stored in memory and lost when the process exits.

    Example:
        storage = MemoryFeedbackStorage()
        storage.store(feedback_record)
        records = storage.query(decision="blocked", limit=100)
    """

    def __init__(self) -> None:
        self._records: list["FeedbackRecord"] = []
        self._lock = threading.RLock()

    def store(self, record: "FeedbackRecord") -> None:
        """Store a feedback record."""
        with self._lock:
            self._records.append(record)

    def query(
        self,
        decision: str | None = None,
        source: str | None = None,
        since: float | None = None,
        limit: int = 1000,
    ) -> list["FeedbackRecord"]:
        """Query feedback records with filters."""
        with self._lock:
            results = []

            for record in self._records:
                # Apply filters
                if decision and record.decision != decision:
                    continue
                if source and record.source != source:
                    continue
                if since and record.timestamp < since:
                    continue

                results.append(record)

                # Check limit
                if len(results) >= limit:
                    break

            return results

    def count(self) -> dict[str, int]:
        """Get counts of records by decision and source."""
        with self._lock:
            counts: dict[str, int] = {
                "total": len(self._records),
                "allowed": 0,
                "blocked": 0,
            }

            source_counts: dict[str, int] = {}

            for record in self._records:
                # Count by decision
                if record.decision == "allowed":
                    counts["allowed"] += 1
                elif record.decision == "blocked":
                    counts["blocked"] += 1

                # Count by source
                source_counts[record.source] = source_counts.get(record.source, 0) + 1

            # Add source counts
            for source, count in source_counts.items():
                counts[f"source_{source}"] = count

            return counts

    def clear(self) -> None:
        """Clear all stored records."""
        with self._lock:
            self._records.clear()


class JSONFileFeedbackStorage:
    """File-based storage for persistent local feedback.

    Stores feedback records as JSONL (one JSON object per line) for
    efficient append operations and easy processing.

    Thread-safe implementation using RLock for concurrent access.

    Example:
        storage = JSONFileFeedbackStorage(path="feedback.jsonl")
        storage.store(feedback_record)
        records = storage.query(since=time.time() - 3600)  # Last hour
    """

    def __init__(self, path: str | Path) -> None:
        """Initialize file storage.

        Args:
            path: Path to JSONL file for storing records
        """
        self.path = Path(path)
        self._lock = threading.RLock()

        # Create parent directory if needed
        self.path.parent.mkdir(parents=True, exist_ok=True)

        # Create file if it doesn't exist
        if not self.path.exists():
            self.path.touch()

    def store(self, record: "FeedbackRecord") -> None:
        """Store a feedback record by appending to file."""
        with self._lock:
            try:
                with open(self.path, "a", encoding="utf-8") as f:
                    json.dump(record.to_dict(), f, ensure_ascii=False)
                    f.write("\n")
            except (OSError, ValueError) as exc:
                logger.error("Failed to write feedback record to %s: %s", self.path, exc)
                raise OSError(f"Failed to write feedback record: {exc}") from exc

    def query(
        self,
        decision: str | None = None,
        source: str | None = None,
        since: float | None = None,
        limit: int = 1000,
    ) -> list["FeedbackRecord"]:
        """Query feedback records with filters."""
        with self._lock:
            results = []

            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue

                        try:
                            data = json.loads(line)
                            record = FeedbackRecord.from_dict(data)

                            # Apply filters
                            if decision and record.decision != decision:
                                continue
                            if source and record.source != source:
                                continue
                            if since and record.timestamp < since:
                                continue

                            results.append(record)

                            # Check limit
                            if len(results) >= limit:
                                break

                        except (json.JSONDecodeError, KeyError, ValueError):
                            # Skip invalid lines
                            continue

            except OSError as exc:
                logger.error("Failed to read feedback records from %s: %s", self.path, exc)
                raise OSError(f"Failed to read feedback records: {exc}") from exc

            return results

    def count(self) -> dict[str, int]:
        """Get counts of records by decision and source."""
        with self._lock:
            counts: dict[str, int] = {
                "total": 0,
                "allowed": 0,
                "blocked": 0,
            }

            source_counts: dict[str, int] = {}

            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue

                        try:
                            data = json.loads(line)
                            record = FeedbackRecord.from_dict(data)

                            counts["total"] += 1

                            # Count by decision
                            if record.decision == "allowed":
                                counts["allowed"] += 1
                            elif record.decision == "blocked":
                                counts["blocked"] += 1

                            # Count by source
                            source_counts[record.source] = source_counts.get(record.source, 0) + 1

                        except (json.JSONDecodeError, KeyError, ValueError):
                            continue

            except OSError as exc:
                logger.error("Failed to count feedback records in %s: %s", self.path, exc)
                raise OSError(f"Failed to count feedback records: {exc}") from exc

            # Add source counts
            for source, count in source_counts.items():
                counts[f"source_{source}"] = count

            return counts

    def clear(self, before_timestamp: float | None = None) -> int:
        """Clear records, optionally keeping recent ones.

        Args:
            before_timestamp: If provided, only delete records before
                this timestamp. If None, delete all records.

        Returns:
            Number of records deleted
        """
        with self._lock:
            if before_timestamp is None:
                # Delete all records
                try:
                    self.path.unlink(missing_ok=True)
                    self.path.touch()
                    return 0
                except OSError as exc:
                    raise OSError(f"Failed to clear records: {exc}") from exc

            # Keep records after timestamp
            kept_records = []
            deleted_count = 0

            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue

                        try:
                            data = json.loads(line)
                            record = FeedbackRecord.from_dict(data)

                            if record.timestamp >= before_timestamp:
                                kept_records.append(record)
                            else:
                                deleted_count += 1

                        except (json.JSONDecodeError, KeyError, ValueError):
                            continue

                # Rewrite file with kept records
                with open(self.path, "w", encoding="utf-8") as f:
                    for record in kept_records:
                        json.dump(record.to_dict(), f, ensure_ascii=False)
                        f.write("\n")

                return deleted_count

            except OSError as exc:
                raise OSError(f"Failed to clear old records: {exc}") from exc


__all__ = [
    "FeedbackStorage",
    "MemoryFeedbackStorage",
    "JSONFileFeedbackStorage",
]
