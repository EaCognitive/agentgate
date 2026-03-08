"""Shared helpers for rendering list payloads in CLI tables."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .formatters import print_ok, print_table


def render_payload_table(
    data: Any,
    *,
    items_key: str,
    empty_message: str,
    headers: list[str],
    row_builder: Callable[[dict[str, Any]], list[str]],
) -> bool:
    """Render a list-like payload as a table and report whether rows existed."""
    items = data if isinstance(data, list) else data.get(items_key, [])
    if not items:
        print_ok(empty_message)
        return False

    rows = [row_builder(item) for item in items if isinstance(item, dict)]
    if not rows:
        print_ok(empty_message)
        return False

    print_table(headers, rows)
    return True
