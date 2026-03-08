"""Redis backend implementations for distributed state."""

from __future__ import annotations

import json
import math
import time
from typing import Any

import redis

from .redis_common import (
    _LUA_RATE_LIMIT,
    cosine_similarity,
    deserialize_pii_entry,
    get_index_key,
    get_key,
    serialize_pii_entry,
)
from .types import CacheEntry, PIIEntry


class RedisRateLimitBackend:
    """
    Redis-based rate limit backend using sorted sets.

    Uses ZADD/ZREMRANGEBYSCORE/ZCARD for atomic sliding window operations.
    Supports connection pooling and graceful fallback.
    """

    def __init__(
        self,
        client: Any,
        key_prefix: str = "agentgate:ratelimit:",
    ) -> None:
        """
        Initialize Redis rate limit backend.

        Args:
            client: Redis client instance
            key_prefix: Prefix for all rate limit keys
        """
        self._client = client
        self._key_prefix = key_prefix
        self._rate_limit_script = self._client.register_script(_LUA_RATE_LIMIT)

    def rate_limit(self, key: str, max_calls: int, window_seconds: float) -> int:
        """
        Fixed-window rate limit using Lua for atomicity.

        Returns the current count or -1 if the limit is exceeded.
        """
        ttl = max(1, math.ceil(window_seconds))
        result = self._rate_limit_script(
            keys=[f"{self._key_prefix}{key}"],
            args=[max_calls, ttl],
        )
        return int(result)

    def record_call(self, key: str, timestamp: float, window_seconds: float) -> int:
        """Record a call atomically using Redis sorted set."""
        redis_key = f"{self._key_prefix}{key}"
        cutoff = timestamp - window_seconds

        pipe = self._client.pipeline()
        pipe.zremrangebyscore(redis_key, "-inf", cutoff)
        pipe.zadd(redis_key, {str(timestamp): timestamp})
        pipe.zcard(redis_key)
        pipe.expire(redis_key, int(window_seconds) + 60)
        results = pipe.execute()

        return int(results[2])

    def get_count(self, key: str, timestamp: float, window_seconds: float) -> int:
        """Get current count without recording."""
        redis_key = f"{self._key_prefix}{key}"
        cutoff = timestamp - window_seconds
        return int(self._client.zcount(redis_key, cutoff, "+inf"))

    def reset(self, key: str | None = None) -> None:
        """Reset counters."""
        if key:
            self._client.delete(f"{self._key_prefix}{key}")
        else:
            pattern = f"{self._key_prefix}*"
            cursor = 0
            while True:
                cursor, keys = self._client.scan(cursor, match=pattern, count=100)
                if keys:
                    self._client.delete(*keys)
                if cursor == 0:
                    break


class RedisCostBackend:
    """
    Redis-based cost tracking backend.

    Uses INCRBYFLOAT for atomic cost accumulation.
    """

    def __init__(
        self,
        client: Any,
        key_prefix: str = "agentgate:cost:",
    ) -> None:
        """
        Initialize Redis cost backend.

        Args:
            client: Redis client instance
            key_prefix: Prefix for all cost keys
        """
        self._client = client
        self._key_prefix = key_prefix

    def add_cost(self, key: str, amount: float) -> float:
        """Add cost atomically using INCRBYFLOAT."""
        redis_key = f"{self._key_prefix}{key}"
        result = self._client.incrbyfloat(redis_key, amount)
        return float(result)

    def get_total(self, key: str) -> float:
        """Get current total cost."""
        redis_key = f"{self._key_prefix}{key}"
        value = self._client.get(redis_key)
        return float(value) if value else 0.0

    def reset(self, key: str | None = None) -> None:
        """Reset cost counters."""
        if key:
            self._client.delete(f"{self._key_prefix}{key}")
        else:
            pattern = f"{self._key_prefix}*"
            cursor = 0
            while True:
                cursor, keys = self._client.scan(cursor, match=pattern, count=100)
                if keys:
                    self._client.delete(*keys)
                if cursor == 0:
                    break


class RedisCacheBackend:
    """
    Redis-based cache backend with embedding similarity search.

    Stores cache entries as JSON with optional embeddings.
    Uses brute-force cosine similarity for search (suitable for small-medium caches).
    For larger caches, consider using Redis Vector Search or a dedicated vector DB.
    """

    def __init__(
        self,
        client: Any,
        key_prefix: str = "agentgate:cache:",
        embedding_key_prefix: str = "agentgate:cache:emb:",
    ) -> None:
        """
        Initialize Redis cache backend.

        Args:
            client: Redis client instance
            key_prefix: Prefix for cache value keys
            embedding_key_prefix: Prefix for embedding storage
        """
        self._client = client
        self._key_prefix = key_prefix
        self._embedding_key_prefix = embedding_key_prefix
        self._embedding_index_key = "agentgate:cache:embedding_index"

    def get(self, key: str) -> Any | None:
        """Get value by exact key."""
        redis_key = f"{self._key_prefix}{key}"
        data = self._client.get(redis_key)
        if data is None:
            return None
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            return None

    def set(
        self,
        key: str,
        value: Any,
        embedding: list[float] | None = None,
        ttl: float | None = None,
    ) -> None:
        """Set a cache entry with optional embedding."""
        redis_key = f"{self._key_prefix}{key}"
        serialized = json.dumps(value)

        if ttl:
            self._client.setex(redis_key, int(ttl), serialized)
        else:
            self._client.set(redis_key, serialized)

        if embedding:
            emb_key = f"{self._embedding_key_prefix}{key}"
            emb_data = json.dumps(
                {
                    "embedding": embedding,
                    "created_at": time.time(),
                    "ttl": ttl,
                }
            )
            if ttl:
                self._client.setex(emb_key, int(ttl), emb_data)
            else:
                self._client.set(emb_key, emb_data)
            self._client.sadd(self._embedding_index_key, key)

    def delete(self, key: str) -> bool:
        """Delete a cache entry."""
        redis_key = f"{self._key_prefix}{key}"
        emb_key = f"{self._embedding_key_prefix}{key}"
        self._client.srem(self._embedding_index_key, key)
        deleted = self._client.delete(redis_key, emb_key)
        return int(deleted) > 0

    def search_similar(
        self,
        embedding: list[float],
        threshold: float = 0.95,
        limit: int = 1,
    ) -> list[CacheEntry]:
        """Search for similar entries by embedding."""
        indexed_keys = self._client.smembers(self._embedding_index_key)
        if not indexed_keys:
            return []

        results: list[tuple[float, str, dict[str, Any]]] = []

        for raw_key in indexed_keys:
            key = raw_key.decode() if isinstance(raw_key, bytes) else raw_key
            emb_key = f"{self._embedding_key_prefix}{key}"
            emb_data = self._client.get(emb_key)

            if emb_data is None:
                self._client.srem(self._embedding_index_key, key)
                continue

            try:
                emb_info = json.loads(emb_data)
            except json.JSONDecodeError:
                continue

            stored_embedding = emb_info.get("embedding")
            if not stored_embedding:
                continue

            similarity = cosine_similarity(embedding, stored_embedding)
            if similarity >= threshold:
                value = self.get(key)
                if value is not None:
                    results.append(
                        (
                            similarity,
                            key,
                            {
                                "value": value,
                                "embedding": stored_embedding,
                                "created_at": emb_info.get("created_at", 0),
                                "ttl": emb_info.get("ttl"),
                            },
                        )
                    )

        results.sort(key=lambda x: x[0], reverse=True)

        return [
            CacheEntry(
                key=key,
                value=data["value"],
                embedding=data["embedding"],
                similarity=sim,
                ttl=data["ttl"],
                created_at=data["created_at"],
            )
            for sim, key, data in results[:limit]
        ]

    def clear(self) -> None:
        """Clear all cache entries."""
        indexed_keys = self._client.smembers(self._embedding_index_key)
        for raw_key in indexed_keys:
            key = raw_key.decode() if isinstance(raw_key, bytes) else raw_key
            self.delete(key)

        pattern = f"{self._key_prefix}*"
        cursor = 0
        while True:
            cursor, keys = self._client.scan(cursor, match=pattern, count=100)
            if keys:
                self._client.delete(*keys)
            if cursor == 0:
                break

        self._client.delete(self._embedding_index_key)


class RedisPIIVaultBackend:
    """
    Redis-based PII vault backend for production deployments.

    Stores PII mappings in Redis with support for:
    - Session isolation via key prefixes
    - TTL-based automatic expiration
    - Atomic operations for concurrent access

    Key structure:
        pii:{session_id}:{placeholder} -> JSON(PIIEntry)
        pii:global:{placeholder} -> JSON(PIIEntry)
        pii:{session_id}:_index -> SET of placeholders

    Example:
        client = create_redis_client(url="redis://localhost:6379/0")
        vault = RedisPIIVaultBackend(client)
        vault.store("<PERSON_1>", "Erick Aleman", "PERSON", session_id="sess123")
    """

    def __init__(
        self,
        client: Any,
        key_prefix: str = "agentgate:pii:",
    ) -> None:
        """
        Initialize Redis PII vault backend.

        Args:
            client: Redis client instance
            key_prefix: Prefix for all PII vault keys
        """
        self._client = client
        self._key_prefix = key_prefix

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
        Store a PII mapping in Redis.

        Args:
            placeholder: The placeholder token (e.g., "<PERSON_1>")
            original: The original PII value
            pii_type: Type of PII
            session_id: Optional session scope
            ttl: Time-to-live in seconds
        """
        entry = PIIEntry(
            placeholder=placeholder,
            original=original,
            pii_type=pii_type,
            session_id=session_id,
            created_at=time.time(),
            ttl=ttl,
        )

        redis_key = get_key(placeholder, session_id, self._key_prefix)
        index_key = get_index_key(session_id, self._key_prefix)
        data = serialize_pii_entry(entry)

        pipe = self._client.pipeline()

        if ttl:
            pipe.setex(redis_key, int(ttl), data)
        else:
            pipe.set(redis_key, data)

        # Add to session index
        pipe.sadd(index_key, placeholder)

        # Set TTL on index if session has TTL
        if ttl:
            pipe.expire(index_key, int(ttl) + 60)  # Extra buffer

        pipe.execute()

    def retrieve(self, placeholder: str, session_id: str | None = None) -> str | None:
        """
        Retrieve original value from placeholder.

        Args:
            placeholder: The placeholder token
            session_id: Session scope

        Returns:
            Original PII value, or None if not found
        """
        redis_key = get_key(placeholder, session_id, self._key_prefix)
        data = self._client.get(redis_key)

        if data is None:
            return None

        entry_data = deserialize_pii_entry(data)
        if entry_data is None:
            return None

        original = entry_data.get("original")
        return original if isinstance(original, str) else None

    def get_all_mappings(self, session_id: str | None = None) -> dict[str, str]:
        """
        Get all placeholder -> original mappings for a session.

        Args:
            session_id: Session scope

        Returns:
            Dictionary of {placeholder: original_value}
        """
        index_key = get_index_key(session_id, self._key_prefix)
        placeholders = self._client.smembers(index_key)

        if not placeholders:
            return {}

        result: dict[str, str] = {}
        expired_placeholders: list[str] = []

        for raw_placeholder in placeholders:
            placeholder = (
                raw_placeholder.decode() if isinstance(raw_placeholder, bytes) else raw_placeholder
            )

            original = self.retrieve(placeholder, session_id)
            if original is not None:
                result[placeholder] = original
            else:
                # Entry expired or missing, clean up index
                expired_placeholders.append(placeholder)

        # Clean up expired placeholders from index
        if expired_placeholders:
            self._client.srem(index_key, *expired_placeholders)

        return result

    def clear_session(self, session_id: str) -> None:
        """
        Clear all PII entries for a specific session.

        Args:
            session_id: Session to clear
        """
        index_key = get_index_key(session_id, self._key_prefix)
        placeholders = self._client.smembers(index_key)

        if placeholders:
            keys_to_delete = [
                get_key(p.decode() if isinstance(p, bytes) else p, session_id, self._key_prefix)
                for p in placeholders
            ]
            keys_to_delete.append(index_key)
            self._client.delete(*keys_to_delete)

    def clear_expired(self) -> int:
        """
        Remove all expired entries.

        Note: Redis handles TTL expiration automatically,
        this method cleans up orphaned index entries.

        Returns:
            Number of orphaned index entries removed
        """
        removed = 0

        # Find all index keys
        pattern = f"{self._key_prefix}*:_index"
        cursor = 0

        while True:
            cursor, keys = self._client.scan(cursor, match=pattern, count=100)

            for raw_key in keys:
                index_key = raw_key.decode() if isinstance(raw_key, bytes) else raw_key

                # Extract session_id from index key
                # Pattern: agentgate:pii:{session_id}:_index
                parts = index_key.replace(self._key_prefix, "").split(":")
                if len(parts) >= 2 and parts[-1] == "_index":
                    session_id = parts[0] if parts[0] != "global" else None

                    # Check each placeholder in the index
                    placeholders = self._client.smembers(index_key)
                    expired = []

                    for raw_p in placeholders:
                        p = raw_p.decode() if isinstance(raw_p, bytes) else raw_p
                        entry_key = get_key(p, session_id, self._key_prefix)

                        if not self._client.exists(entry_key):
                            expired.append(p)
                            removed += 1

                    if expired:
                        self._client.srem(index_key, *expired)

            if cursor == 0:
                break

        return removed


def create_redis_client(
    url: str | None = None,
    host: str = "localhost",
    port: int = 6379,
    db: int = 0,
    password: str | None = None,
    **kwargs: Any,
) -> Any:
    """
    Create a Redis client with connection pooling.

    Args:
        url: Redis URL (e.g., "redis://localhost:6379/0")
        host: Redis host (used if url not provided)
        port: Redis port
        db: Database number
        password: Redis password
        **kwargs: Additional arguments passed to Redis client

    Returns:
        Redis client instance

    Raises:
        ImportError: If redis package is not installed
    """
    if not redis:
        raise ImportError("Redis package required. Install with: pip install ea-agentgate[redis]")

    if url:
        return redis.from_url(url, **kwargs)

    return redis.Redis(
        host=host,
        port=port,
        db=db,
        password=password,
        **kwargs,
    )


__all__ = [
    "RedisRateLimitBackend",
    "RedisCostBackend",
    "RedisCacheBackend",
    "RedisPIIVaultBackend",
    "create_redis_client",
]
