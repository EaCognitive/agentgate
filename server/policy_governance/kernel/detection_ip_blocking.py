"""
IP blocking management for threat detection.

Provides centralized IP blocking with TTL-aware expiry,
Redis-backed distributed state, and in-memory fallback.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, TYPE_CHECKING, cast

from .threat_detector_config import ThreatDetectorState

if TYPE_CHECKING:
    from redis import Redis

logger = logging.getLogger(__name__)


class IPBlockingManager:
    """
    Manages IP blocking state with Redis and in-memory storage.

    Provides TTL-aware blocking, distributed state via Redis,
    and automatic expiry pruning for in-memory entries.
    """

    DEFAULT_BLOCK_DURATION = 3600  # 1 hour

    def __init__(
        self,
        state: ThreatDetectorState,
        redis_client: "Redis | None" = None,
    ):
        """
        Initialize IP blocking manager.

        Args:
            state: Shared threat detector state.
            redis_client: Optional Redis client.
        """
        self._state = state
        self._redis = redis_client

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked.

        Checks the in-memory TTL-aware store first,
        then falls back to Redis if available.

        Args:
            ip: The IP address to check.

        Returns:
            True if the IP is currently blocked.
        """
        if ip in self._state.blocked_ips:
            return True

        if self._redis:
            try:
                return bool(self._redis.exists(f"blocked_ip:{ip}"))
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.warning("Redis check failed: %s", e)

        return False

    def block_ip(
        self,
        ip: str,
        reason: str,
        duration: int = DEFAULT_BLOCK_DURATION,
    ) -> None:
        """Block an IP address for a given duration.

        Stores the block with an expiry timestamp in-memory
        and, when available, in Redis with a native TTL key.

        Args:
            ip: The IP address to block.
            reason: Human-readable reason for blocking.
            duration: Block duration in seconds.
        """
        expiry = time.time() + duration
        self._state.ip_state.blocked_ips_expiry[ip] = (
            expiry,
            reason,
        )

        if self._redis:
            try:
                payload = json.dumps(
                    {
                        "reason": reason,
                        "expires_at": expiry,
                    }
                )
                self._redis.setex(
                    f"blocked_ip:{ip}",
                    duration,
                    payload,
                )
                self._redis.sadd("blocked_ips", ip)
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.warning("Redis block failed: %s", e)

        logger.warning(
            "IP blocked: %s (reason: %s, duration: %ds)",
            ip,
            reason,
            duration,
        )

    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address.

        Removes the IP from both in-memory and Redis stores.

        Args:
            ip: The IP address to unblock.

        Returns:
            True if the IP was previously blocked.
        """
        was_blocked = ip in self._state.blocked_ips
        self._state.ip_state.blocked_ips_expiry.pop(ip, None)

        if self._redis:
            try:
                self._redis.delete(f"blocked_ip:{ip}")
                self._redis.srem("blocked_ips", ip)
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.warning("Redis unblock failed: %s", e)

        return was_blocked

    def get_blocked_ips(self) -> set[str]:
        """Get all currently blocked (non-expired) IPs.

        Merges in-memory and Redis sources. Stale Redis
        index entries are pruned automatically.

        Returns:
            Set of currently blocked IP addresses.
        """
        blocked = self._state.blocked_ips.copy()

        if self._redis:
            try:
                redis_blocked = self._redis.smembers("blocked_ips")
                if redis_blocked:
                    for ip in cast("set[str]", redis_blocked):
                        if self._redis.exists(f"blocked_ip:{ip}"):
                            blocked.add(ip)
                        else:
                            self._redis.srem("blocked_ips", ip)
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.warning("Redis get blocked failed: %s", e)

        return blocked

    def get_blocked_ip_details(
        self,
    ) -> dict[str, dict[str, Any]]:
        """Get details for all currently blocked IPs.

        Returns a mapping of IP to its block metadata
        including the reason and expiry timestamp.

        Returns:
            Dict mapping IP to {reason, expires_at}.
        """
        now = time.time()
        details: dict[str, dict[str, Any]] = {}
        expiry_store = self._state.ip_state.blocked_ips_expiry
        for ip, (expiry, reason) in list(expiry_store.items()):
            if expiry <= now:
                del expiry_store[ip]
                continue
            details[ip] = {
                "reason": reason,
                "expires_at": expiry,
            }
        return details


__all__ = [
    "IPBlockingManager",
]
