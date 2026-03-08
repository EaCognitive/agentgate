"""Shared utilities and constants for Redis backends."""

from __future__ import annotations

import json
import math
from typing import Any

from .types import PIIEntry

_LUA_RATE_LIMIT = """
local current = redis.call('GET', KEYS[1])
if current and tonumber(current) >= tonumber(ARGV[1]) then
    return -1
else
    local new = redis.call('INCR', KEYS[1])
    if tonumber(new) == 1 then
        redis.call('EXPIRE', KEYS[1], ARGV[2])
    end
    return new
end
"""


def get_key(placeholder: str, session_id: str | None, key_prefix: str) -> str:
    """Get Redis key for a PII placeholder."""
    scope = session_id if session_id else "global"
    return f"{key_prefix}{scope}:{placeholder}"


def get_index_key(session_id: str | None, key_prefix: str) -> str:
    """Get Redis key for session index set."""
    scope = session_id if session_id else "global"
    return f"{key_prefix}{scope}:_index"


def serialize_pii_entry(entry: PIIEntry) -> str:
    """Serialize a PIIEntry to JSON."""
    return json.dumps(
        {
            "placeholder": entry.placeholder,
            "original": entry.original,
            "pii_type": entry.pii_type,
            "session_id": entry.session_id,
            "created_at": entry.created_at,
            "ttl": entry.ttl,
        }
    )


def deserialize_pii_entry(data: Any) -> dict[str, Any] | None:
    """Deserialize JSON data to a dictionary."""
    try:
        decoded = json.loads(data)
    except json.JSONDecodeError:
        return None
    if not isinstance(decoded, dict):
        return None
    return decoded


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute cosine similarity between two vectors."""
    if len(a) != len(b):
        return 0.0

    dot_product = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))

    if norm_a == 0 or norm_b == 0:
        return 0.0

    return dot_product / (norm_a * norm_b)


__all__ = [
    "_LUA_RATE_LIMIT",
    "get_key",
    "get_index_key",
    "serialize_pii_entry",
    "deserialize_pii_entry",
    "cosine_similarity",
]
