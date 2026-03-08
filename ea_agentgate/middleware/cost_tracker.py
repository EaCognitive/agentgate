"""Cost tracking middleware."""

from __future__ import annotations

from typing import Any
from collections.abc import Callable

from .base import Middleware, MiddlewareContext
from ..exceptions import BudgetExceededError


class CostTracker(Middleware):
    """
    Tracks and limits costs of tool execution.

    Prevents runaway costs from expensive operations.

    Example:
        tracker = CostTracker(
            max_budget=10.00,
            cost_fn=lambda tool, inputs: TOOL_COSTS.get(tool, 0.01),
        )

        # After execution:
        print(f"Total cost: ${tracker.total_cost:.2f}")
    """

    def __init__(
        self,
        max_budget: float | None = None,
        max_per_call: float | None = None,
        cost_fn: Callable[[str, dict[str, Any]], float] | None = None,
        default_cost: float = 0.0,
    ):
        """
        Initialize cost tracker.

        Args:
            max_budget: Maximum total cost allowed
            max_per_call: Maximum cost per individual call
            cost_fn: Function to calculate cost for a tool call
            default_cost: Default cost if cost_fn not provided or returns None
        """
        super().__init__()
        self.max_budget = max_budget
        self.max_per_call = max_per_call
        self.cost_fn = cost_fn
        self.default_cost = default_cost
        self.total_cost = 0.0
        self._call_costs: list[tuple[str, float]] = []  # (tool, cost) history

    def _estimate_cost(self, tool: str, inputs: dict[str, Any]) -> float:
        """Estimate cost for a tool call."""
        if self.cost_fn:
            cost = self.cost_fn(tool, inputs)
            if cost is not None:
                return cost
        return self.default_cost

    def before(self, ctx: MiddlewareContext) -> None:
        """Check budget before execution."""
        estimated_cost = self._estimate_cost(ctx.tool, ctx.inputs)

        # Check per-call limit
        if self.max_per_call is not None and estimated_cost > self.max_per_call:
            raise BudgetExceededError(
                f"Call cost ${estimated_cost:.2f} exceeds per-call limit ${self.max_per_call:.2f}",
                current_cost=estimated_cost,
                max_budget=self.max_per_call,
            )

        # Check total budget
        if self.max_budget is not None:
            if self.total_cost + estimated_cost > self.max_budget:
                msg = (
                    f"Budget exceeded: ${self.total_cost:.2f} + "
                    f"${estimated_cost:.2f} > ${self.max_budget:.2f}"
                )
                raise BudgetExceededError(
                    msg,
                    current_cost=self.total_cost,
                    max_budget=self.max_budget,
                )

        # Store estimated cost in context for after()
        ctx.cost = estimated_cost

    def after(self, ctx: MiddlewareContext, _result: Any, error: Exception | None) -> None:
        """Record cost after execution."""
        # Only charge for successful calls (configurable)
        if error is None:
            cost = ctx.cost
            self.total_cost += cost
            self._call_costs.append((ctx.tool, cost))
            ctx.trace.context.cost = cost

    def reset(self) -> None:
        """Reset cost tracking."""
        self.total_cost = 0.0
        self._call_costs.clear()

    def get_breakdown(self) -> dict[str, float]:
        """Get cost breakdown by tool."""
        breakdown: dict[str, float] = {}
        for tool, cost in self._call_costs:
            breakdown[tool] = breakdown.get(tool, 0.0) + cost
        return breakdown
