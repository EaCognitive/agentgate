"""Semantic caching middleware using embeddings."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

from .base import Middleware, MiddlewareContext

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from ..backends import CacheBackend, AsyncCacheBackend
    from ..providers.base import LLMProvider


@dataclass
class CacheStats:
    """Statistics for cache performance."""

    hits: int = 0
    misses: int = 0
    errors: int = 0

    @property
    def total(self) -> int:
        """Total cache lookups."""
        return self.hits + self.misses

    @property
    def hit_rate(self) -> float:
        """Cache hit rate (0-1)."""
        if self.total == 0:
            return 0.0
        return self.hits / self.total

    def reset(self) -> None:
        """Reset statistics."""
        self.hits = 0
        self.misses = 0
        self.errors = 0


@dataclass
class CacheConfig:
    """Configuration for semantic caching."""

    similarity_threshold: float = 0.95
    ttl: float | None = 3600
    cache_tools: set[str] | None = None
    exclude_tools: set[str] = field(default_factory=set)
    include_tool_in_key: bool = True


class SemanticCache(Middleware):
    """
    Semantic caching based on input similarity.

    Caches tool results and retrieves them when similar inputs are detected
    using embedding-based similarity search.

    Example:
        from ea_agentgate.providers import OpenAIProvider
        from ea_agentgate.backends.memory import MemoryCacheBackend

        cache = SemanticCache(
            provider=OpenAIProvider(),
            backend=MemoryCacheBackend(),
            similarity_threshold=0.95,
            ttl=3600,  # 1 hour
        )

        # Only cache specific tools
        cache = SemanticCache(
            provider=OpenAIProvider(),
            cache_tools=["search", "query"],  # Only cache these
        )

        # Exclude certain tools from caching
        cache = SemanticCache(
            provider=OpenAIProvider(),
            exclude_tools=["write_file", "delete"],  # Never cache these
        )
    """

    def __init__(
        self,
        provider: "LLMProvider",
        backend: "CacheBackend | None" = None,
        similarity_threshold: float = 0.95,
        ttl: float | None = 3600,
        cache_tools: list[str] | None = None,
        exclude_tools: list[str] | None = None,
        include_tool_in_key: bool = True,
        async_provider: Any | None = None,
        async_backend: "AsyncCacheBackend | None" = None,
    ) -> None:
        """
        Initialize semantic cache.

        Args:
            provider: LLM provider for generating embeddings
            backend: Cache backend (defaults to in-memory)
            similarity_threshold: Minimum similarity for cache hit (0-1)
            ttl: Time-to-live for cache entries in seconds (None = no expiration)
            cache_tools: Only cache these tools (None = all tools)
            exclude_tools: Never cache these tools
            include_tool_in_key: Include tool name in cache key
            async_provider: Optional async LLM provider (must have aembed method)
            async_backend: Optional async cache backend
        """
        self.provider = provider

        self.config = CacheConfig(
            similarity_threshold=similarity_threshold,
            ttl=ttl,
            cache_tools=set(cache_tools) if cache_tools else None,
            exclude_tools=set(exclude_tools) if exclude_tools else set(),
            include_tool_in_key=include_tool_in_key,
        )

        self.stats = CacheStats()

        if backend is not None:
            self._backend = backend
        else:
            from ..backends.memory import MemoryCacheBackend

            self._backend = MemoryCacheBackend()

        # Async support
        self._async_provider = async_provider
        self._async_backend = async_backend

    def _should_cache(self, tool: str) -> bool:
        """Check if tool should be cached."""
        if tool in self.config.exclude_tools:
            return False
        if self.config.cache_tools is not None and tool not in self.config.cache_tools:
            return False
        return True

    def before(self, ctx: MiddlewareContext) -> None:
        """Check cache before tool execution."""
        if not self._should_cache(ctx.tool):
            return

        try:
            input_text = self._serialize_inputs(ctx.tool, ctx.inputs)
            embedding = self.provider.embed(input_text)

            results = self._backend.search_similar(
                embedding,
                threshold=self.config.similarity_threshold,
                limit=1,
            )

            if results:
                cached_entry = results[0]
                self.stats.hits += 1
                ctx.metadata["cache_hit"] = True
                ctx.metadata["cache_similarity"] = cached_entry.similarity
                ctx.metadata["cached_result"] = cached_entry.value.get("result")
            else:
                self.stats.misses += 1
                ctx.metadata["cache_hit"] = False
                ctx.metadata["input_embedding"] = embedding

        except (TypeError, ValueError, AttributeError) as e:
            # JSON serialization or embedding generation errors
            logger.debug("Cache lookup failed (input issue): %s", e)
            self.stats.errors += 1
            ctx.metadata["cache_hit"] = False
        except Exception as e:
            # Provider or backend errors should not crash the application
            logger.debug("Cache lookup failed: %s", type(e).__name__)
            self.stats.errors += 1
            ctx.metadata["cache_hit"] = False

    def after(self, ctx: MiddlewareContext, result: Any, error: Exception | None) -> None:
        """Store result in cache after successful execution."""
        if not self._should_cache(ctx.tool):
            return

        if error is not None:
            return

        if ctx.metadata.get("cache_hit"):
            return

        embedding = ctx.metadata.get("input_embedding")
        if embedding is None:
            return

        try:
            input_text = self._serialize_inputs(ctx.tool, ctx.inputs)
            cache_key = self._get_cache_key(ctx.tool, input_text)

            self._backend.set(
                cache_key,
                {"result": result, "tool": ctx.tool},
                embedding=embedding,
                ttl=self.config.ttl,
            )

        except (TypeError, ValueError, AttributeError) as e:
            # JSON serialization or cache key generation errors
            logger.debug("Cache store failed (input issue): %s", e)
            self.stats.errors += 1
        except Exception as e:
            # Backend or provider errors should not crash the application
            logger.debug("Cache store failed: %s", type(e).__name__)
            self.stats.errors += 1

    def _serialize_inputs(self, tool: str, inputs: dict[str, Any]) -> str:
        """Serialize inputs for embedding."""
        data = inputs.copy()
        if self.config.include_tool_in_key:
            data["__tool__"] = tool
        try:
            return json.dumps(data, sort_keys=True, default=str)
        except (TypeError, ValueError):
            return str(data)

    def _get_cache_key(self, tool: str, input_text: str) -> str:
        """Generate cache key from inputs."""
        key_data = f"{tool}:{input_text}" if self.config.include_tool_in_key else input_text
        return hashlib.sha256(key_data.encode()).hexdigest()[:32]

    def clear(self) -> None:
        """Clear all cached entries."""
        self._backend.clear()

    def invalidate(self, tool: str | None = None) -> None:
        """
        Invalidate cache entries.

        Args:
            tool: Currently unused; clears all entries regardless of tool.
                  Future versions may support per-tool invalidation.
        """
        _ = tool  # Reserved for future per-tool invalidation
        self._backend.clear()

    # -------------------------------------------------------------------------
    # Async Methods
    # -------------------------------------------------------------------------

    def is_async_native(self) -> bool:
        """Return True if async provider and backend are configured."""
        return self._async_provider is not None and self._async_backend is not None

    async def abefore(self, ctx: MiddlewareContext) -> None:
        """Async check cache before tool execution."""
        if self._async_provider is None:
            # Fall back to sync via thread pool
            await asyncio.to_thread(self.before, ctx)
            return

        if not self._should_cache(ctx.tool):
            return

        try:
            input_text = self._serialize_inputs(ctx.tool, ctx.inputs)
            embedding = await self._async_provider.aembed(input_text)

            # Use async backend if available, otherwise sync backend in thread pool
            if self._async_backend:
                results = await self._async_backend.asearch_similar(
                    embedding,
                    threshold=self.config.similarity_threshold,
                    limit=1,
                )
            else:
                results = await asyncio.to_thread(
                    self._backend.search_similar,
                    embedding,
                    self.config.similarity_threshold,
                    1,
                )

            if results:
                cached_entry = results[0]
                self.stats.hits += 1
                ctx.metadata["cache_hit"] = True
                ctx.metadata["cache_similarity"] = cached_entry.similarity
                ctx.metadata["cached_result"] = cached_entry.value.get("result")
            else:
                self.stats.misses += 1
                ctx.metadata["cache_hit"] = False
                ctx.metadata["input_embedding"] = embedding

        except (TypeError, ValueError, AttributeError) as e:
            # JSON serialization or embedding generation errors
            logger.debug("Async cache lookup failed (input issue): %s", e)
            self.stats.errors += 1
            ctx.metadata["cache_hit"] = False
        except Exception as e:
            # Provider or backend errors should not crash the application
            logger.debug("Async cache lookup failed: %s", type(e).__name__)
            self.stats.errors += 1
            ctx.metadata["cache_hit"] = False

    async def aafter(self, ctx: MiddlewareContext, result: Any, error: Exception | None) -> None:
        """Async store result in cache after successful execution."""
        if self._async_provider is None:
            # Fall back to sync via thread pool
            await asyncio.to_thread(self.after, ctx, result, error)
            return

        if not self._should_cache(ctx.tool):
            return

        if error is not None:
            return

        if ctx.metadata.get("cache_hit"):
            return

        embedding = ctx.metadata.get("input_embedding")
        if embedding is None:
            return

        try:
            input_text = self._serialize_inputs(ctx.tool, ctx.inputs)
            cache_key = self._get_cache_key(ctx.tool, input_text)

            if self._async_backend:
                await self._async_backend.aset(
                    cache_key,
                    {"result": result, "tool": ctx.tool},
                    embedding=embedding,
                    ttl=self.config.ttl,
                )
            else:
                await asyncio.to_thread(
                    self._backend.set,
                    cache_key,
                    {"result": result, "tool": ctx.tool},
                    embedding,
                    self.config.ttl,
                )

        except (TypeError, ValueError, AttributeError) as e:
            # JSON serialization or cache key generation errors
            logger.debug("Async cache store failed (input issue): %s", e)
            self.stats.errors += 1
        except Exception as e:
            # Backend or provider errors should not crash the application
            logger.debug("Async cache store failed: %s", type(e).__name__)
            self.stats.errors += 1

    async def aclear(self) -> None:
        """Async clear all cached entries."""
        if self._async_backend:
            await self._async_backend.aclear()
        else:
            await asyncio.to_thread(self._backend.clear)


__all__ = [
    "SemanticCache",
    "CacheStats",
]
