"""Audit logging middleware."""

from __future__ import annotations

import json
import sys
from contextlib import ExitStack
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, TextIO
from collections.abc import Callable

from .base import Middleware, MiddlewareContext


@dataclass
class AuditConfig:
    """Configuration for audit logging."""

    include_inputs: bool = True
    include_outputs: bool = True
    include_errors: bool = True
    redact_keys: set[str] = field(default_factory=set)


class AuditLog(Middleware):
    """
    Logs all tool calls for audit trails.

    Supports multiple output destinations and can be used as a context manager
    for automatic resource cleanup.

    Example:
        # Log to stdout
        audit = AuditLog()

        # Log to file (with context manager for automatic cleanup)
        with AuditLog(destination="agent_audit.jsonl") as audit:
            agent = Agent(middleware=[audit])
            # ... use agent ...

        # Log to custom function
        audit = AuditLog(destination=lambda entry: send_to_datadog(entry))

        # Log to database URL (future)
        audit = AuditLog(destination="postgres://...")
    """

    def __init__(
        self,
        destination: str | Path | TextIO | Callable[[dict[str, Any]], None] | None = None,
        *,
        include_inputs: bool = True,
        include_outputs: bool = True,
        include_errors: bool = True,
        redact_keys: list[str] | None = None,
    ):
        """
        Initialize audit logger.

        Args:
            destination: Where to log (file path, file object, or callback)
            include_inputs: Include tool inputs in log
            include_outputs: Include tool outputs in log
            include_errors: Include error details in log
            redact_keys: Keys to redact from inputs (e.g., ["password", "api_key"])
        """
        super().__init__()
        self.destination = destination

        self.config = AuditConfig(
            include_inputs=include_inputs,
            include_outputs=include_outputs,
            include_errors=include_errors,
            redact_keys=set(redact_keys or []),
        )

        self._file: TextIO | None = None
        self._callback: Callable[[dict[str, Any]], None] | None = None
        self._owns_file: bool = False  # Track if we opened the file
        self._destination_path: str | Path | None = None
        self._exit_stack = ExitStack()

        if destination is None:
            self._file = sys.stdout
        elif isinstance(destination, (str, Path)):
            dest_str = str(destination)
            if dest_str.startswith(("postgres://", "mysql://", "http://", "https://")):
                raise NotImplementedError(f"Destination type not yet supported: {dest_str}")
            # Open file eagerly so logging works without context manager
            self._destination_path = destination
            self._file = self._exit_stack.enter_context(
                Path(destination).open("a", encoding="utf-8")
            )
            self._owns_file = True
        elif callable(destination):
            self._callback = destination
        else:
            # Assume it's a file-like object passed in
            self._file = destination

        self._entries: list[dict[str, Any]] = []

    def __enter__(self) -> "AuditLog":
        """Enter context manager (file is already open from __init__)."""
        return self

    def __exit__(self, *_: Any) -> None:
        """Exit context manager and clean up resources."""
        self.close()

    def _redact(self, data: dict[str, Any]) -> dict[str, Any]:
        """Redact sensitive keys from data."""
        if not self.config.redact_keys:
            return data

        redacted: dict[str, Any] = {}
        for key, value in data.items():
            key_lower = key.lower()
            matches = key_lower in self.config.redact_keys or any(
                r in key_lower for r in self.config.redact_keys
            )
            if matches:
                redacted[key] = "[REDACTED]"
            elif isinstance(value, dict):
                redacted[key] = self._redact(value)
            else:
                redacted[key] = value
        return redacted

    def _log(self, entry: dict[str, Any]) -> None:
        """Write log entry to destination."""
        self._entries.append(entry)

        if self._callback:
            self._callback(entry)
        elif self._file:
            try:
                line = json.dumps(entry)
            except (TypeError, ValueError):
                # Non-serializable output; stringify the output field
                entry["output"] = str(entry.get("output"))
                line = json.dumps(entry)
            self._file.write(line + "\n")
            self._file.flush()

    def before(self, ctx: MiddlewareContext) -> None:
        """Log tool call start."""
        entry: dict[str, Any] = {
            "event": "tool_call_start",
            "timestamp": datetime.now().isoformat(),
            "trace_id": ctx.trace.id,
            "tool": ctx.tool,
            "agent_id": ctx.agent_id,
            "session_id": ctx.session_id,
            "user_id": ctx.user_id,
        }

        if self.config.include_inputs:
            entry["inputs"] = self._redact(ctx.inputs)

        self._log(entry)

    def after(self, ctx: MiddlewareContext, result: Any, error: Exception | None) -> None:
        """Log tool call completion."""
        entry: dict[str, Any] = {
            "event": "tool_call_end",
            "timestamp": datetime.now().isoformat(),
            "trace_id": ctx.trace.id,
            "tool": ctx.tool,
            "status": "error" if error else "success",
            "duration_ms": ctx.trace.timing.duration_ms,
            "cost": ctx.cost,
        }

        if self.config.include_outputs and error is None:
            entry["output"] = result

        if self.config.include_errors and error is not None:
            entry["error"] = {
                "type": type(error).__name__,
                "message": str(error),
            }

        self._log(entry)

    def get_entries(self) -> list[dict[str, Any]]:
        """Get all log entries (for testing/inspection)."""
        return self._entries.copy()

    def close(self) -> None:
        """Close file handle if we opened it."""
        if self._owns_file and self._file:
            self._exit_stack.close()
            self._file = None
            self._owns_file = False
