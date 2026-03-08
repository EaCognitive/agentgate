"""Shared types for LLM provider integrations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from ..trace import Trace


@dataclass
class ToolCallResult:
    """Result of validating a tool call.

    Attributes:
        id: Unique identifier for the tool call (from the provider)
        name: Name of the tool being called
        args: Arguments passed to the tool
        blocked: Whether the call was blocked by middleware
        reason: Reason for blocking (if blocked)
        trace: Associated execution trace
    """

    id: str
    name: str
    args: dict[str, Any]
    blocked: bool = False
    reason: str | None = None
    trace: "Trace | None" = None
