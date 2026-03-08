"""Shared types for backends."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class CacheEntry:
    """Entry in the cache with metadata."""

    key: str
    value: Any
    embedding: list[float] | None = None
    similarity: float = 1.0
    ttl: float | None = None
    created_at: float = 0.0


@dataclass
class PIIEntry:
    """Entry in the PII vault storing a redacted value mapping."""

    placeholder: str  # e.g., "<PERSON_1>"
    original: str  # e.g., "Erick Aleman"
    pii_type: str  # e.g., "PERSON", "EMAIL", "SSN"
    session_id: str | None = None  # For session-scoped storage
    created_at: float = 0.0  # Unix timestamp
    ttl: float | None = None  # Time-to-live in seconds
