"""In-memory backend implementations."""

from __future__ import annotations

import math
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from .types import CacheEntry, PIIEntry


class MemoryRateLimitBackend:
    """
    In-memory rate limit backend using sliding window.

    Uses a dictionary mapping keys to lists of timestamps.
    Thread-safe via internal locking.
    """

    def __init__(self) -> None:
        self._calls: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.RLock()

    def record_call(self, key: str, timestamp: float, window_seconds: float) -> int:
        """Record a call and return count within window."""
        with self._lock:
            cutoff = timestamp - window_seconds
            self._calls[key] = [t for t in self._calls[key] if t > cutoff]
            self._calls[key].append(timestamp)
            return len(self._calls[key])

    def get_count(self, key: str, timestamp: float, window_seconds: float) -> int:
        """Get current count without recording."""
        with self._lock:
            cutoff = timestamp - window_seconds
            return len([t for t in self._calls[key] if t > cutoff])

    def reset(self, key: str | None = None) -> None:
        """Reset counters."""
        with self._lock:
            if key:
                self._calls.pop(key, None)
            else:
                self._calls.clear()


class MemoryCostBackend:
    """
    In-memory cost tracking backend.

    Simple dictionary-based accumulator.
    Thread-safe via internal locking.
    """

    def __init__(self) -> None:
        self._costs: dict[str, float] = {}
        self._lock = threading.RLock()

    def add_cost(self, key: str, amount: float) -> float:
        """Add cost and return new total."""
        with self._lock:
            current = self._costs.get(key, 0.0)
            new_total = current + amount
            self._costs[key] = new_total
            return new_total

    def get_total(self, key: str) -> float:
        """Get current total cost."""
        with self._lock:
            return self._costs.get(key, 0.0)

    def reset(self, key: str | None = None) -> None:
        """Reset cost counters."""
        with self._lock:
            if key:
                self._costs.pop(key, None)
            else:
                self._costs.clear()


@dataclass
class _CacheItem:
    """Internal cache item with metadata."""

    value: Any
    embedding: list[float] | None
    ttl: float | None
    created_at: float


class MemoryCacheBackend:
    """
    In-memory cache backend with embedding similarity search.

    Supports TTL-based expiration and cosine similarity search.
    Thread-safe via internal locking.
    """

    def __init__(self) -> None:
        self._cache: dict[str, _CacheItem] = {}
        self._lock = threading.RLock()

    def get(self, key: str) -> Any | None:
        """Get value by exact key."""
        with self._lock:
            item = self._cache.get(key)
            if item is None:
                return None

            if item.ttl is not None:
                if time.time() - item.created_at > item.ttl:
                    del self._cache[key]
                    return None

            return item.value

    def set(
        self,
        key: str,
        value: Any,
        embedding: list[float] | None = None,
        ttl: float | None = None,
    ) -> None:
        """Set a cache entry."""
        with self._lock:
            self._cache[key] = _CacheItem(
                value=value,
                embedding=embedding,
                ttl=ttl,
                created_at=time.time(),
            )

    def delete(self, key: str) -> bool:
        """Delete a cache entry."""
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False

    def search_similar(
        self,
        embedding: list[float],
        threshold: float = 0.95,
        limit: int = 1,
    ) -> list[CacheEntry]:
        """Search for similar entries by embedding using cosine similarity."""
        with self._lock:
            now = time.time()
            results: list[tuple[float, str, _CacheItem]] = []

            for key, item in list(self._cache.items()):
                if item.ttl is not None and now - item.created_at > item.ttl:
                    del self._cache[key]
                    continue

                if item.embedding is None:
                    continue

                similarity = self._cosine_similarity(embedding, item.embedding)
                if similarity >= threshold:
                    results.append((similarity, key, item))

            results.sort(key=lambda x: x[0], reverse=True)

            return [
                CacheEntry(
                    key=key,
                    value=item.value,
                    embedding=item.embedding,
                    similarity=sim,
                    ttl=item.ttl,
                    created_at=item.created_at,
                )
                for sim, key, item in results[:limit]
            ]

    def clear(self) -> None:
        """Clear all cache entries."""
        with self._lock:
            self._cache.clear()

    @staticmethod
    def _cosine_similarity(a: list[float], b: list[float]) -> float:
        """Compute cosine similarity between two vectors."""
        if not a or not b:
            return 0.0

        if len(a) != len(b):
            return 0.0

        dot_product = sum(x * y for x, y in zip(a, b))
        norm_a = math.sqrt(sum(x * x for x in a))
        norm_b = math.sqrt(sum(x * x for x in b))

        if norm_a == 0 or norm_b == 0:
            return 0.0

        return dot_product / (norm_a * norm_b)


class MemoryPIIVaultBackend:
    """
    In-memory PII vault backend for development and testing.

    Stores PII mappings in memory with session isolation and TTL support.
    Thread-safe via internal locking.

    Example:
        vault = MemoryPIIVaultBackend()
        vault.store("<PERSON_1>", "Erick Aleman", "PERSON", session_id="session123")
        original = vault.retrieve("<PERSON_1>", session_id="session123")
        # Returns: "Erick Aleman"

    Warning:
        Data is lost when the process ends. Use RedisPIIVaultBackend for production.
    """

    def __init__(self) -> None:
        # Session-scoped storage: session_id -> {placeholder -> PIIEntry}
        self._sessions: dict[str, dict[str, PIIEntry]] = defaultdict(dict)
        # Global storage for session-less operations
        self._global: dict[str, PIIEntry] = {}
        self._lock = threading.RLock()

    def store(
        self,
        placeholder: str,
        original: str,
        pii_type: str,
        *,
        session_id: str | None = None,
        ttl: float | None = None,
    ) -> None:
        """
        Store a PII mapping.

        Args:
            placeholder: The placeholder token (e.g., "<PERSON_1>")
            original: The original PII value (e.g., "Erick Aleman")
            pii_type: Type of PII (e.g., "PERSON", "EMAIL", "SSN")
            session_id: Optional session scope for isolation
            ttl: Time-to-live in seconds (None = no expiration)
        """
        entry = PIIEntry(
            placeholder=placeholder,
            original=original,
            pii_type=pii_type,
            session_id=session_id,
            created_at=time.time(),
            ttl=ttl,
        )

        with self._lock:
            if session_id is not None:
                self._sessions[session_id][placeholder] = entry
            else:
                self._global[placeholder] = entry

    def retrieve(self, placeholder: str, session_id: str | None = None) -> str | None:
        """
        Retrieve original value from placeholder.

        Args:
            placeholder: The placeholder token to look up
            session_id: Session scope to search in

        Returns:
            Original PII value, or None if not found/expired
        """
        with self._lock:
            entry = self._get_entry(placeholder, session_id)
            if entry is None:
                return None

            # Check TTL expiration
            if entry.ttl is not None:
                if time.time() - entry.created_at > entry.ttl:
                    self._delete_entry(placeholder, session_id)
                    return None

            return entry.original

    def get_all_mappings(self, session_id: str | None = None) -> dict[str, str]:
        """
        Get all placeholder -> original mappings for a session.

        Excludes expired entries.

        Args:
            session_id: Session scope (None for global mappings)

        Returns:
            Dictionary of {placeholder: original_value}
        """
        with self._lock:
            now = time.time()
            result: dict[str, str] = {}

            if session_id is not None:
                store = self._sessions.get(session_id, {})
            else:
                store = self._global

            expired_keys: list[str] = []
            for placeholder, entry in store.items():
                # Check TTL expiration
                if entry.ttl is not None and now - entry.created_at > entry.ttl:
                    expired_keys.append(placeholder)
                    continue
                result[placeholder] = entry.original

            # Clean up expired entries
            for key in expired_keys:
                del store[key]

            return result

    def clear_session(self, session_id: str) -> None:
        """
        Clear all PII entries for a specific session.

        Args:
            session_id: Session to clear
        """
        with self._lock:
            self._sessions.pop(session_id, None)

    def clear_expired(self) -> int:
        """
        Remove all expired entries from all sessions.

        Returns:
            Number of entries removed
        """
        with self._lock:
            now = time.time()
            removed = 0

            # Clean global store
            expired_global = [
                k
                for k, v in self._global.items()
                if v.ttl is not None and now - v.created_at > v.ttl
            ]
            for key in expired_global:
                del self._global[key]
                removed += 1

            # Clean session stores
            empty_sessions: list[str] = []
            for session_id, store in self._sessions.items():
                expired_keys = [
                    k for k, v in store.items() if v.ttl is not None and now - v.created_at > v.ttl
                ]
                for key in expired_keys:
                    del store[key]
                    removed += 1
                if not store:
                    empty_sessions.append(session_id)

            # Clean up empty sessions
            for session_id in empty_sessions:
                del self._sessions[session_id]

            return removed

    def _get_entry(self, placeholder: str, session_id: str | None) -> PIIEntry | None:
        """Get entry from appropriate store."""
        if session_id is not None:
            return self._sessions.get(session_id, {}).get(placeholder)
        return self._global.get(placeholder)

    def _delete_entry(self, placeholder: str, session_id: str | None) -> None:
        """Delete entry from appropriate store."""
        if session_id is not None:
            store = self._sessions.get(session_id, {})
            store.pop(placeholder, None)
        else:
            self._global.pop(placeholder, None)


__all__ = [
    "MemoryRateLimitBackend",
    "MemoryCostBackend",
    "MemoryCacheBackend",
    "MemoryPIIVaultBackend",
]
