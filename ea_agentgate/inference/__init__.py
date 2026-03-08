"""Async inference infrastructure for ML models.

This module provides process-pool based inference to avoid GIL blocking
and achieve low-latency ML predictions in async contexts.
"""

from __future__ import annotations

from .sidecar import InferenceSidecar, classify_async

__all__ = [
    "InferenceSidecar",
    "classify_async",
]
