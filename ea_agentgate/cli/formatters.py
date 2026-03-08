"""Output formatters for the AgentGate CLI."""

import json
import sys
from typing import Any


def print_json(data: Any) -> None:
    """Print data as formatted JSON."""
    print(json.dumps(data, indent=2, default=str))


def print_table(
    headers: list[str],
    rows: list[list[str]],
    max_col: int = 40,
) -> None:
    """Print a formatted table with auto-sized columns."""
    widths: list[int] = []
    for i, header in enumerate(headers):
        col_max = len(header)
        for row in rows:
            if i < len(row):
                col_max = max(col_max, len(_trunc(str(row[i]), max_col)))
        widths.append(min(col_max + 1, max_col))

    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers))
    print(fmt.format(*["-" * w for w in widths]))
    for row in rows:
        cells = []
        for i in range(len(headers)):
            val = str(row[i]) if i < len(row) else "-"
            cells.append(_trunc(val, max_col))
        print(fmt.format(*cells))


def print_kv(pairs: list[tuple[str, Any]], indent: int = 2) -> None:
    """Print key-value pairs in aligned columns."""
    if not pairs:
        return
    max_key = max(len(k) for k, _ in pairs)
    prefix = " " * indent
    for key, value in pairs:
        val = str(value) if value is not None else "-"
        print(f"{prefix}{key:<{max_key + 2}} {val}")


def print_error(msg: str) -> None:
    """Print an error message to stderr."""
    print(f"Error: {msg}", file=sys.stderr)


def print_ok(msg: str) -> None:
    """Print a success message."""
    print(f"  {msg}")


def _trunc(text: str, max_len: int) -> str:
    """Truncate text with ellipsis if it exceeds max_len."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."
