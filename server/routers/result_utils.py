"""Shared SQLAlchemy result helpers for auth-related routers."""

from __future__ import annotations

from typing import Any


def unwrap_result_row(row: Any) -> Any:
    """Unwrap SQLAlchemy row wrappers to their first scalar value."""
    if row is None:
        return None
    if isinstance(row, tuple):
        return row[0] if row else None
    mapping = getattr(row, "_mapping", None)
    if mapping:
        return next(iter(mapping.values()), row)
    try:
        return row[0]
    except (TypeError, KeyError, IndexError):
        return row


def result_one_or_none(result: Any) -> Any:
    """Return one scalar row from an execute result."""
    if hasattr(result, "scalar_one_or_none"):
        return result.scalar_one_or_none()
    if hasattr(result, "one_or_none"):
        return result.one_or_none()
    if not hasattr(result, "first"):
        return None
    return unwrap_result_row(result.first())


def result_all(result: Any) -> list[Any]:
    """Return all scalar rows from an execute result."""
    if hasattr(result, "scalars"):
        return list(result.scalars().all())
    if not hasattr(result, "all"):
        return []
    return [unwrap_result_row(row) for row in result.all()]
