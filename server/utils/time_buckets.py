"""Time bucketing utilities for data aggregation.

Provides functions for grouping time-series data into fixed-size time buckets,
commonly used for charting and analytics endpoints.
"""

from datetime import datetime
from typing import Any, TypeVar
from collections.abc import Callable

T = TypeVar("T")


def bucket_datetime(
    dt: datetime,
    bucket_minutes: int,
) -> datetime:
    """
    Round a datetime to the nearest time bucket boundary.

    Args:
        dt: The datetime to round
        bucket_minutes: Size of each bucket in minutes (e.g., 60 for hourly)

    Returns:
        A datetime rounded down to the nearest bucket boundary
    """
    return dt.replace(
        minute=(dt.minute // bucket_minutes) * bucket_minutes,
        second=0,
        microsecond=0,
    )


def aggregate_by_time_bucket(
    items: list[tuple[datetime, T]],
    bucket_minutes: int,
    aggregator: Callable[[list[T]], Any],
) -> dict[str, Any]:
    """
    Aggregate items by time bucket using a custom aggregation function.

    Args:
        items: List of (timestamp, value) tuples
        bucket_minutes: Size of each bucket in minutes
        aggregator: Function that takes a list of values and returns aggregated result

    Returns:
        Dictionary mapping ISO-format timestamp strings to aggregated results
    """
    buckets: dict[str, list[T]] = {}

    for timestamp, value in items:
        bucket_time = bucket_datetime(timestamp, bucket_minutes)
        bucket_key = bucket_time.isoformat()

        if bucket_key not in buckets:
            buckets[bucket_key] = []

        buckets[bucket_key].append(value)

    return {bucket_key: aggregator(values) for bucket_key, values in sorted(buckets.items())}


__all__ = ["bucket_datetime", "aggregate_by_time_bucket"]
