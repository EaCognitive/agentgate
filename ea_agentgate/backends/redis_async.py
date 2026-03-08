"""Async Redis backend implementations for distributed state."""

from __future__ import annotations

import json
import math
import time
from typing import Any

from redis.asyncio import Redis as AsyncRedis

from .redis_common import (
    _LUA_RATE_LIMIT,
    cosine_similarity,
    deserialize_pii_entry,
    get_index_key,
    get_key,
    serialize_pii_entry,
)
from .types import CacheEntry, PIIEntry


class AsyncRedisRateLimitBackend:
    """
    Async Redis-based rate limit backend using sorted sets.

    Uses ZADD/ZREMRANGEBYSCORE/ZCARD for atomic sliding window operations.
    All operations are non-blocking and use redis.asyncio.
    """

    def __init__(
        self,
        client: Any,
        key_prefix: str = "agentgate:ratelimit:",
    ) -> None:
        """
        Initialize async Redis rate limit backend.

        Args:
            client: Async Redis client instance (redis.asyncio.Redis)
            key_prefix: Prefix for all rate limit keys
        """
        self._client = client
        self._key_prefix = key_prefix
        self._rate_limit_script = self._client.register_script(_LUA_RATE_LIMIT)

    async def arate_limit(self, key: str, max_calls: int, window_seconds: float) -> int:
        """
        Fixed-window rate limit using Lua for atomicity (async).

        Returns the current count or -1 if the limit is exceeded.
        """
        ttl = max(1, math.ceil(window_seconds))
        result = await self._rate_limit_script(
            keys=[f"{self._key_prefix}{key}"],
            args=[max_calls, ttl],
        )
        return int(result)

    async def rate_limit(self, key: str, max_calls: int, window_seconds: float) -> int:
        """Alias for arate_limit to match sync API naming."""
        return await self.arate_limit(key, max_calls, window_seconds)

    async def arecord_call(self, key: str, timestamp: float, window_seconds: float) -> int:
        """Record a call atomically using Redis pipeline."""
        redis_key = f"{self._key_prefix}{key}"
        cutoff = timestamp - window_seconds

        async with self._client.pipeline(transaction=True) as pipe:
            pipe.zremrangebyscore(redis_key, "-inf", cutoff)
            pipe.zadd(redis_key, {str(timestamp): timestamp})
            pipe.zcard(redis_key)
            pipe.expire(redis_key, int(window_seconds) + 60)
            results = await pipe.execute()

        return int(results[2])

    async def aget_count(self, key: str, timestamp: float, window_seconds: float) -> int:
        """Get current count without recording."""
        redis_key = f"{self._key_prefix}{key}"
        cutoff = timestamp - window_seconds
        return int(await self._client.zcount(redis_key, cutoff, "+inf"))

    async def areset(self, key: str | None = None) -> None:
        """Reset counters."""
        if key:
            await self._client.delete(f"{self._key_prefix}{key}")
        else:
            pattern = f"{self._key_prefix}*"
            cursor = 0
            while True:
                cursor, keys = await self._client.scan(cursor, match=pattern, count=100)
                if keys:
                    await self._client.delete(*keys)
                if cursor == 0:
                    break


class AsyncRedisCostBackend:
    """
    Async Redis-based cost tracking backend.

    Uses INCRBYFLOAT for atomic cost accumulation.
    """

    def __init__(
        self,
        client: Any,
        key_prefix: str = "agentgate:cost:",
    ) -> None:
        """
        Initialize async Redis cost backend.

        Args:
            client: Async Redis client instance
            key_prefix: Prefix for all cost keys
        """
        self._client = client
        self._key_prefix = key_prefix

    async def aadd_cost(self, key: str, amount: float) -> float:
        """Add cost atomically using INCRBYFLOAT."""
        redis_key = f"{self._key_prefix}{key}"
        result = await self._client.incrbyfloat(redis_key, amount)
        return float(result)

    async def aget_total(self, key: str) -> float:
        """Get current total cost."""
        redis_key = f"{self._key_prefix}{key}"
        value = await self._client.get(redis_key)
        return float(value) if value else 0.0

    async def areset(self, key: str | None = None) -> None:
        """Reset cost counters."""
        if key:
            await self._client.delete(f"{self._key_prefix}{key}")
        else:
            pattern = f"{self._key_prefix}*"
            cursor = 0
            while True:
                cursor, keys = await self._client.scan(cursor, match=pattern, count=100)
                if keys:
                    await self._client.delete(*keys)
                if cursor == 0:
                    break


class AsyncRedisCacheBackend:
    """
    Async Redis-based cache backend with BATCHED embedding similarity search.

    Key improvement over sync version: Uses MGET for batch reads instead of
    N+1 queries, providing significant performance benefits in async context.
    """

    def __init__(
        self,
        client: Any,
        key_prefix: str = "agentgate:cache:",
        embedding_key_prefix: str = "agentgate:cache:emb:",
    ) -> None:
        """
        Initialize async Redis cache backend.

        Args:
            client: Async Redis client instance
            key_prefix: Prefix for cache value keys
            embedding_key_prefix: Prefix for embedding storage
        """
        self._client = client
        self._key_prefix = key_prefix
        self._embedding_key_prefix = embedding_key_prefix
        self._embedding_index_key = "agentgate:cache:embedding_index"

    async def aget(self, key: str) -> Any | None:
        """Async get value by exact key."""
        redis_key = f"{self._key_prefix}{key}"
        data = await self._client.get(redis_key)
        if data is None:
            return None
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            return None

    async def aset(
        self,
        key: str,
        value: Any,
        embedding: list[float] | None = None,
        ttl: float | None = None,
    ) -> None:
        """Async set a cache entry with optional embedding."""
        redis_key = f"{self._key_prefix}{key}"
        serialized = json.dumps(value)

        # Use pipeline for atomicity and efficiency
        async with self._client.pipeline(transaction=False) as pipe:
            if ttl:
                pipe.setex(redis_key, int(ttl), serialized)
            else:
                pipe.set(redis_key, serialized)

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
                    pipe.setex(emb_key, int(ttl), emb_data)
                else:
                    pipe.set(emb_key, emb_data)
                pipe.sadd(self._embedding_index_key, key)

            await pipe.execute()

    async def adelete(self, key: str) -> bool:
        """Async delete a cache entry."""
        redis_key = f"{self._key_prefix}{key}"
        emb_key = f"{self._embedding_key_prefix}{key}"
        await self._client.srem(self._embedding_index_key, key)
        deleted = await self._client.delete(redis_key, emb_key)
        return int(deleted) > 0

    async def _compute_similarities(
        self,
        embedding: list[float],
        keys: list[str],
        emb_data_list: list,
        threshold: float,
    ) -> tuple[list[tuple[float, str, dict[str, Any]]], list[str]]:
        """
        Compute similarities for embeddings and filter by threshold.

        Returns:
            Tuple of (matching_results, stale_keys)
        """
        results: list[tuple[float, str, dict[str, Any]]] = []
        stale_keys: list[str] = []

        for key, emb_data in zip(keys, emb_data_list):
            if emb_data is None:
                stale_keys.append(key)
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
                results.append((similarity, key, emb_info))

        return results, stale_keys

    async def asearch_similar(
        self,
        embedding: list[float],
        threshold: float = 0.95,
        limit: int = 1,
    ) -> list[CacheEntry]:
        """
        Async search for similar entries using BATCHED MGET.

        This fixes the N+1 query problem present in sync version by:
        1. Fetching all embedding keys in one SMEMBERS call
        2. Fetching all embeddings in one MGET call
        3. Computing similarities locally
        4. Fetching matching values in one MGET call

        This reduces Redis round-trips from O(n) to O(1).
        """
        indexed_keys = await self._client.smembers(self._embedding_index_key)
        if not indexed_keys:
            return []

        # Decode keys
        keys = [
            raw_key.decode() if isinstance(raw_key, bytes) else raw_key for raw_key in indexed_keys
        ]

        # BATCH: Fetch all embeddings in one MGET call
        emb_keys = [f"{self._embedding_key_prefix}{k}" for k in keys]
        emb_data_list = await self._client.mget(emb_keys)

        # Compute similarities and identify stale keys
        results, stale_keys = await self._compute_similarities(
            embedding, keys, emb_data_list, threshold
        )

        # Clean up stale keys asynchronously (fire and forget)
        if stale_keys:
            await self._client.srem(self._embedding_index_key, *stale_keys)

        # Sort by similarity descending and limit
        results.sort(key=lambda x: x[0], reverse=True)
        results = results[:limit]

        if not results:
            return []

        # BATCH: Fetch values for matching entries
        value_keys = [f"{self._key_prefix}{r[1]}" for r in results]
        values = await self._client.mget(value_keys)

        return [
            CacheEntry(
                key=key,
                value=json.loads(value) if value else None,
                embedding=emb_info["embedding"],
                similarity=sim,
                ttl=emb_info.get("ttl"),
                created_at=emb_info.get("created_at", 0),
            )
            for (sim, key, emb_info), value in zip(results, values)
            if value is not None
        ]

    async def aclear(self) -> None:
        """Async clear all cache entries."""
        # Get all indexed keys
        indexed_keys = await self._client.smembers(self._embedding_index_key)

        # Delete in batches using pipeline
        if indexed_keys:
            async with self._client.pipeline(transaction=False) as pipe:
                for raw_key in indexed_keys:
                    key = raw_key.decode() if isinstance(raw_key, bytes) else raw_key
                    pipe.delete(f"{self._key_prefix}{key}")
                    pipe.delete(f"{self._embedding_key_prefix}{key}")
                await pipe.execute()

        # Scan and delete any remaining cache keys
        pattern = f"{self._key_prefix}*"
        cursor = 0
        while True:
            cursor, keys = await self._client.scan(cursor, match=pattern, count=100)
            if keys:
                await self._client.delete(*keys)
            if cursor == 0:
                break

        await self._client.delete(self._embedding_index_key)


class AsyncRedisPIIVaultBackend:
    """
    Async Redis-based PII vault backend for production deployments.

    Async version of RedisPIIVaultBackend with session isolation and TTL.
    """

    def __init__(
        self,
        client: Any,
        key_prefix: str = "agentgate:pii:",
    ) -> None:
        self._client = client
        self._key_prefix = key_prefix

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

        async with self._client.pipeline(transaction=False) as pipe:
            if ttl:
                pipe.setex(redis_key, int(ttl), data)
            else:
                pipe.set(redis_key, data)

            pipe.sadd(index_key, placeholder)

            if ttl:
                pipe.expire(index_key, int(ttl) + 60)

            await pipe.execute()

    async def aretrieve(self, placeholder: str, session_id: str | None = None) -> str | None:
        """
        Async retrieve original value from placeholder.

        Args:
            placeholder: The placeholder token to look up
            session_id: Session scope to search in

        Returns:
            Original PII value, or None if not found/expired
        """
        redis_key = get_key(placeholder, session_id, self._key_prefix)
        data = await self._client.get(redis_key)

        if data is None:
            return None

        entry_data = deserialize_pii_entry(data)
        if entry_data is None:
            return None

        original = entry_data.get("original")
        return original if isinstance(original, str) else None

    async def aget_all_mappings(self, session_id: str | None = None) -> dict[str, str]:
        """
        Async get all placeholder -> original mappings for a session.

        Args:
            session_id: Session scope (None for global mappings)

        Returns:
            Dictionary of {placeholder: original_value}
        """
        index_key = get_index_key(session_id, self._key_prefix)
        placeholders = await self._client.smembers(index_key)

        if not placeholders:
            return {}

        result: dict[str, str] = {}
        expired_placeholders: list[str] = []

        for raw_placeholder in placeholders:
            placeholder = (
                raw_placeholder.decode() if isinstance(raw_placeholder, bytes) else raw_placeholder
            )

            original = await self.aretrieve(placeholder, session_id)
            if original is not None:
                result[placeholder] = original
            else:
                expired_placeholders.append(placeholder)

        if expired_placeholders:
            await self._client.srem(index_key, *expired_placeholders)

        return result

    async def aclear_session(self, session_id: str) -> None:
        """
        Async clear all PII entries for a specific session.

        Args:
            session_id: Session to clear
        """
        index_key = get_index_key(session_id, self._key_prefix)
        placeholders = await self._client.smembers(index_key)

        if placeholders:
            keys_to_delete = [
                get_key(p.decode() if isinstance(p, bytes) else p, session_id, self._key_prefix)
                for p in placeholders
            ]
            keys_to_delete.append(index_key)
            await self._client.delete(*keys_to_delete)

    async def aclear_expired(self) -> int:
        """
        Async remove all expired entries.

        Returns:
            Number of entries removed
        """
        removed = 0
        pattern = f"{self._key_prefix}*:_index"
        cursor = 0

        while True:
            cursor, keys = await self._client.scan(cursor, match=pattern, count=100)

            for raw_key in keys:
                index_key = raw_key.decode() if isinstance(raw_key, bytes) else raw_key
                parts = index_key.replace(self._key_prefix, "").split(":")
                if len(parts) >= 2 and parts[-1] == "_index":
                    session_id = parts[0] if parts[0] != "global" else None

                    placeholders = await self._client.smembers(index_key)
                    expired: list[str] = []

                    for raw_p in placeholders:
                        p = raw_p.decode() if isinstance(raw_p, bytes) else raw_p
                        entry_key = get_key(p, session_id, self._key_prefix)

                        if not await self._client.exists(entry_key):
                            expired.append(p)
                            removed += 1

                    if expired:
                        await self._client.srem(index_key, *expired)

            if cursor == 0:
                break

        return removed


async def create_async_redis_client(
    url: str | None = None,
    host: str = "localhost",
    port: int = 6379,
    db: int = 0,
    password: str | None = None,
    **kwargs: Any,
) -> Any:
    """
    Create an async Redis client.

    Args:
        url: Redis URL (e.g., "redis://localhost:6379/0")
        host: Redis host (used if url not provided)
        port: Redis port
        db: Database number
        password: Redis password
        **kwargs: Additional arguments passed to Redis client

    Returns:
        Async Redis client instance

    Raises:
        ImportError: If redis package is not installed

    Example:
        redis = await create_async_redis_client(url="redis://localhost:6379/0")
        backend = AsyncRedisRateLimitBackend(redis)
    """
    if AsyncRedis is None:
        raise ImportError("Redis package required. Install with: pip install ea-agentgate[redis]")

    if url:
        return AsyncRedis.from_url(url, **kwargs)

    return AsyncRedis(
        host=host,
        port=port,
        db=db,
        password=password,
        **kwargs,
    )


__all__ = [
    "AsyncRedisRateLimitBackend",
    "AsyncRedisCostBackend",
    "AsyncRedisCacheBackend",
    "AsyncRedisPIIVaultBackend",
    "create_async_redis_client",
]
