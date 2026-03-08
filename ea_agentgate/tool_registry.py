"""Tool registration and lookup for Agent.

Encapsulates the tool registry (name -> ToolDef mapping) and provides
a clean interface for registering, retrieving, and querying tools.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from collections.abc import Callable


@dataclass
class ToolDef:
    """Definition of a registered tool."""

    name: str
    fn: Callable[..., Any]
    requires_approval: bool = False
    cost: float | None = None
    compensation: Callable[..., Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class ToolRegistry:
    """Registry of tools available for agent execution.

    Manages tool definitions including their names, functions,
    approval requirements, cost metadata, and compensation handlers.

    Example:
        registry = ToolRegistry()
        registry.register("read_file", read_file_fn)
        tool = registry.get("read_file")
    """

    def __init__(self) -> None:
        """Initialize an empty tool registry."""
        self._tools: dict[str, ToolDef] = {}

    def register(
        self,
        name: str,
        fn: Callable[..., Any],
        requires_approval: bool = False,
        cost: float | None = None,
    ) -> None:
        """Register a tool with the registry.

        Args:
            name: Name to register the tool under.
            fn: The tool function.
            requires_approval: Whether tool requires human approval.
            cost: Optional cost per invocation.
        """
        tool_def = ToolDef(
            name=name,
            fn=fn,
            requires_approval=requires_approval,
            cost=cost,
        )
        self._tools[name] = tool_def

    def get(self, name: str) -> ToolDef:
        """Retrieve a tool definition by name.

        Args:
            name: Name of the tool to retrieve.

        Returns:
            The ToolDef for the named tool.

        Raises:
            KeyError: If the tool is not registered.
        """
        if name not in self._tools:
            raise KeyError(f"Tool '{name}' not registered")
        return self._tools[name]

    def set_compensation(
        self,
        tool_name: str,
        compensation: Callable[..., Any],
    ) -> None:
        """Set or update the compensation function for a tool.

        Args:
            tool_name: Name of the tool.
            compensation: Compensation callable invoked during rollback.
        """
        if tool_name in self._tools:
            self._tools[tool_name].compensation = compensation

    @property
    def tools(self) -> dict[str, ToolDef]:
        """Return a shallow copy of all registered tools."""
        return self._tools.copy()

    def __contains__(self, name: str) -> bool:
        """Check whether a tool name is registered."""
        return name in self._tools
