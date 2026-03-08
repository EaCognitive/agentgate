"""Backend protocols for distributed state management."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from .types import CacheEntry


@runtime_checkable
class RateLimitBackend(Protocol):
    """
    Backend for rate limit tracking.

    Supports sliding window rate limiting with atomic operations.
    """

    def record_call(self, key: str, timestamp: float, window_seconds: float) -> int:
        """
        Record a call and return the count within the window.

        This should atomically:
        1. Remove entries older than (timestamp - window_seconds)
        2. Add the new timestamp
        3. Return the current count

        Args:
            key: The scope key (e.g., "user:123", "tool:read_file")
            timestamp: Unix timestamp of the call
            window_seconds: The sliding window size

        Returns:
            Number of calls in the current window (including this one)
        """
        raise NotImplementedError

    def get_count(self, key: str, timestamp: float, window_seconds: float) -> int:
        """
        Get current call count without recording.

        Args:
            key: The scope key
            timestamp: Current timestamp
            window_seconds: The sliding window size

        Returns:
            Number of calls in the current window
        """
        raise NotImplementedError

    def reset(self, key: str | None = None) -> None:
        """
        Reset rate limit counters.

        Args:
            key: Specific key to reset, or None to reset all
        """
        raise NotImplementedError


@runtime_checkable
class CostBackend(Protocol):
    """
    Backend for cost tracking.

    Supports atomic cost accumulation for budget enforcement.
    """

    def add_cost(self, key: str, amount: float) -> float:
        """
        Add cost and return new total.

        Args:
            key: The scope key (e.g., "session:abc", "user:123")
            amount: Cost amount to add

        Returns:
            New total cost for the key
        """
        raise NotImplementedError

    def get_total(self, key: str) -> float:
        """
        Get current total cost.

        Args:
            key: The scope key

        Returns:
            Current total cost
        """
        raise NotImplementedError

    def reset(self, key: str | None = None) -> None:
        """
        Reset cost counters.

        Args:
            key: Specific key to reset, or None to reset all
        """
        raise NotImplementedError


@runtime_checkable
class CacheBackend(Protocol):
    """
    Backend for semantic caching.

    Supports embedding-based similarity search for cache lookups.
    """

    def get(self, key: str) -> Any | None:
        """
        Get value by exact key.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found/expired
        """
        raise NotImplementedError

    def set(
        self,
        key: str,
        value: Any,
        embedding: list[float] | None = None,
        ttl: float | None = None,
    ) -> None:
        """
        Set a cache entry.

        Args:
            key: Cache key
            value: Value to cache
            embedding: Optional embedding vector for similarity search
            ttl: Time-to-live in seconds (None = no expiration)
        """
        raise NotImplementedError

    def delete(self, key: str) -> bool:
        """
        Delete a cache entry.

        Args:
            key: Cache key

        Returns:
            True if entry was deleted, False if not found
        """
        raise NotImplementedError

    def search_similar(
        self,
        embedding: list[float],
        threshold: float = 0.95,
        limit: int = 1,
    ) -> list[CacheEntry]:
        """
        Search for similar entries by embedding.

        Args:
            embedding: Query embedding vector
            threshold: Minimum similarity threshold (0-1)
            limit: Maximum number of results

        Returns:
            List of matching cache entries sorted by similarity (descending)
        """
        raise NotImplementedError

    def clear(self) -> None:
        """Clear all cache entries."""
        raise NotImplementedError


# -----------------------------------------------------------------------------
# Async Protocol Interfaces
# -----------------------------------------------------------------------------


@runtime_checkable
class AsyncRateLimitBackend(Protocol):
    """
    Async backend for rate limit tracking.

    Supports sliding window rate limiting with atomic operations.
    Use with redis.asyncio or other async Redis clients.
    """

    async def arecord_call(self, key: str, timestamp: float, window_seconds: float) -> int:
        """
        Async record a call and return the count within the window.

        This should atomically:
        1. Remove entries older than (timestamp - window_seconds)
        2. Add the new timestamp
        3. Return the current count

        Args:
            key: The scope key (e.g., "user:123", "tool:read_file")
            timestamp: Unix timestamp of the call
            window_seconds: The sliding window size

        Returns:
            Number of calls in the current window (including this one)
        """
        raise NotImplementedError

    async def aget_count(self, key: str, timestamp: float, window_seconds: float) -> int:
        """
        Async get current call count without recording.

        Args:
            key: The scope key
            timestamp: Current timestamp
            window_seconds: The sliding window size

        Returns:
            Number of calls in the current window
        """
        raise NotImplementedError

    async def areset(self, key: str | None = None) -> None:
        """
        Async reset rate limit counters.

        Args:
            key: Specific key to reset, or None to reset all
        """
        raise NotImplementedError


@runtime_checkable
class AsyncCostBackend(Protocol):
    """
    Async backend for cost tracking.

    Supports atomic cost accumulation for budget enforcement.
    """

    async def aadd_cost(self, key: str, amount: float) -> float:
        """
        Async add cost and return new total.

        Args:
            key: The scope key (e.g., "session:abc", "user:123")
            amount: Cost amount to add

        Returns:
            New total cost for the key
        """
        raise NotImplementedError

    async def aget_total(self, key: str) -> float:
        """
        Async get current total cost.

        Args:
            key: The scope key

        Returns:
            Current total cost
        """
        raise NotImplementedError

    async def areset(self, key: str | None = None) -> None:
        """
        Async reset cost counters.

        Args:
            key: Specific key to reset, or None to reset all
        """
        raise NotImplementedError


@runtime_checkable
class AsyncCacheBackend(Protocol):
    """
    Async backend for semantic caching.

    Supports embedding-based similarity search for cache lookups.
    """

    async def aget(self, key: str) -> Any | None:
        """
        Async get value by exact key.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found/expired
        """
        raise NotImplementedError

    async def aset(
        self,
        key: str,
        value: Any,
        embedding: list[float] | None = None,
        ttl: float | None = None,
    ) -> None:
        """
        Async set a cache entry.

        Args:
            key: Cache key
            value: Value to cache
            embedding: Optional embedding vector for similarity search
            ttl: Time-to-live in seconds (None = no expiration)
        """
        raise NotImplementedError

    async def adelete(self, key: str) -> bool:
        """
        Async delete a cache entry.

        Args:
            key: Cache key

        Returns:
            True if entry was deleted, False if not found
        """
        raise NotImplementedError

    async def asearch_similar(
        self,
        embedding: list[float],
        threshold: float = 0.95,
        limit: int = 1,
    ) -> list[CacheEntry]:
        """
        Async search for similar entries by embedding.

        Uses batched operations (MGET) for efficiency.

        Args:
            embedding: Query embedding vector
            threshold: Minimum similarity threshold (0-1)
            limit: Maximum number of results

        Returns:
            List of matching cache entries sorted by similarity (descending)
        """
        raise NotImplementedError

    async def aclear(self) -> None:
        """Async clear all cache entries."""
        raise NotImplementedError


# -----------------------------------------------------------------------------
# PII Vault Protocol Interfaces
# -----------------------------------------------------------------------------


@runtime_checkable
class PIIVaultBackend(Protocol):
    """
    Backend for PII (Personally Identifiable Information) vault storage.

    Stores mappings between placeholders and original PII values,
    enabling bi-directional anonymization (redact on input, rehydrate on output).

    Example:
        vault.store("<PERSON_1>", "Erick Aleman", "PERSON", session_id="abc123")
        original = vault.retrieve("<PERSON_1>", session_id="abc123")
        # Returns: "Erick Aleman"
    """

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
        raise NotImplementedError

    def retrieve(self, placeholder: str, session_id: str | None = None) -> str | None:
        """
        Retrieve original value from placeholder.

        Args:
            placeholder: The placeholder token to look up
            session_id: Session scope to search in

        Returns:
            Original PII value, or None if not found/expired
        """
        raise NotImplementedError

    def get_all_mappings(self, session_id: str | None = None) -> dict[str, str]:
        """
        Get all placeholder -> original mappings for a session.

        Used during rehydration to replace all placeholders in output.

        Args:
            session_id: Session scope (None for global mappings)

        Returns:
            Dictionary of {placeholder: original_value}
        """
        raise NotImplementedError

    def clear_session(self, session_id: str) -> None:
        """
        Clear all PII entries for a specific session.

        Should be called when a session ends to clean up sensitive data.

        Args:
            session_id: Session to clear
        """
        raise NotImplementedError

    def clear_expired(self) -> int:
        """
        Remove all expired entries.

        Returns:
            Number of entries removed
        """
        raise NotImplementedError


@runtime_checkable
class AsyncPIIVaultBackend(Protocol):
    """
    Async backend for PII vault storage.

    Async version of PIIVaultBackend for use with async Redis or other async stores.
    """

    async def astore(
        self,
        placeholder: str,
        original: str,
        pii_type: str,
        *,
        session_id: str | None = None,
        ttl: float | None = None,
    ) -> None:
        """
        Async store a PII mapping.

        Args:
            placeholder: The placeholder token (e.g., "<PERSON_1>")
            original: The original PII value (e.g., "Erick Aleman")
            pii_type: Type of PII (e.g., "PERSON", "EMAIL", "SSN")
            session_id: Optional session scope for isolation
            ttl: Time-to-live in seconds (None = no expiration)
        """
        raise NotImplementedError

    async def aretrieve(self, placeholder: str, session_id: str | None = None) -> str | None:
        """
        Async retrieve original value from placeholder.

        Args:
            placeholder: The placeholder token to look up
            session_id: Session scope to search in

        Returns:
            Original PII value, or None if not found/expired
        """
        raise NotImplementedError

    async def aget_all_mappings(self, session_id: str | None = None) -> dict[str, str]:
        """
        Async get all placeholder -> original mappings for a session.

        Args:
            session_id: Session scope (None for global mappings)

        Returns:
            Dictionary of {placeholder: original_value}
        """
        raise NotImplementedError

    async def aclear_session(self, session_id: str) -> None:
        """
        Async clear all PII entries for a specific session.

        Args:
            session_id: Session to clear
        """
        raise NotImplementedError

    async def aclear_expired(self) -> int:
        """
        Async remove all expired entries.

        Returns:
            Number of entries removed
        """
        raise NotImplementedError
