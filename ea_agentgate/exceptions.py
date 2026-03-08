"""Exceptions for ea_agentgate."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .trace import Trace


class AgentGateError(Exception):
    """Base exception for agentgate with rich debugging context.

    All AgentGate exceptions include:
    - Detailed error messages
    - Middleware/tool context
    - Trace ID for debugging
    - Documentation links
    - Suggested fixes

    Example:
        try:
            agent.call("dangerous_tool", path="/")
        except ValidationError as e:
            print(f"Error: {e}")
            print(f"Trace ID: {e.trace_id}")
            print(f"Suggested Fix: {e.suggested_fix}")
            print(f"Documentation: {e.docs_url}")
    """

    def __init__(
        self,
        message: str,
        *,
        middleware: str | None = None,
        tool: str | None = None,
        trace_id: str | None = None,
        context: dict[str, Any] | None = None,
        docs_url: str | None = None,
        suggested_fix: str | None = None,
    ):
        """Initialize enhanced exception.

        Args:
            message: Human-readable error message
            middleware: Name of middleware that raised the error
            tool: Name of tool being executed
            trace_id: Trace ID for debugging
            context: Additional context dictionary
            docs_url: Link to relevant documentation
            suggested_fix: Actionable suggestion to fix the error
        """
        self.middleware = middleware
        self.tool = tool
        self.trace_id = trace_id
        self.context = context or {}
        self.docs_url = docs_url
        self.suggested_fix = suggested_fix
        super().__init__(message)

    def __str__(self) -> str:
        """Format error with debugging information."""
        parts = [f"Error: {super().__str__()}"]

        if self.middleware:
            parts.append(f"Middleware: {self.middleware}")
        if self.tool:
            parts.append(f"Tool: {self.tool}")
        if self.trace_id:
            parts.append(f"Trace ID: {self.trace_id}")
        if self.context:
            parts.append("Context:")
            for key, value in self.context.items():
                parts.append(f"  - {key}: {value}")
        if self.suggested_fix:
            parts.append(f"Suggested Fix: {self.suggested_fix}")
        if self.docs_url:
            parts.append(f"Documentation: {self.docs_url}")

        return "\n".join(parts)


class AgentSafetyError(AgentGateError):
    """Base exception for safety-related errors.

    Deprecated: Use AgentGateError directly. This is kept for
    backward compatibility.
    """


class ValidationError(AgentSafetyError):
    """Raised when validation fails.

    Common causes:
    - Blocked file paths
    - Dangerous command patterns
    - Prompt injection detected
    - Tool not allowed
    """

    def __init__(
        self,
        message: str,
        *,
        middleware: str | None = None,
        tool: str | None = None,
        trace_id: str | None = None,
        context: dict[str, Any] | None = None,
        suggested_fix: str | None = None,
    ):
        docs_url = "https://docs.agentgate.io/middleware/validation"
        super().__init__(
            message,
            middleware=middleware,
            tool=tool,
            trace_id=trace_id,
            context=context,
            docs_url=docs_url,
            suggested_fix=suggested_fix,
        )


class RateLimitError(AgentSafetyError):
    """Raised when rate limit is exceeded.

    The agent has exceeded its allowed rate of tool calls.
    Wait for the cooldown period before retrying.
    """

    def __init__(
        self,
        message: str,
        *,
        retry_after: float | None = None,
        middleware: str | None = None,
        tool: str | None = None,
        trace_id: str | None = None,
        context: dict[str, Any] | None = None,
    ):
        self.retry_after = retry_after
        suggested_fix = None
        if retry_after:
            suggested_fix = f"Wait {retry_after:.1f} seconds before retrying"

        super().__init__(
            message,
            middleware=middleware,
            tool=tool,
            trace_id=trace_id,
            context=context or {},
            docs_url="https://docs.agentgate.io/middleware/rate-limiter",
            suggested_fix=suggested_fix,
        )


class BudgetExceededError(AgentSafetyError):
    """Raised when cost budget is exceeded.

    The agent has spent more than the allowed budget for API calls.
    """

    def __init__(
        self,
        message: str,
        *,
        current_cost: float,
        max_budget: float,
        middleware: str | None = None,
        tool: str | None = None,
        trace_id: str | None = None,
    ):
        self.current_cost = current_cost
        self.max_budget = max_budget

        context = {
            "current_cost": f"${current_cost:.4f}",
            "max_budget": f"${max_budget:.4f}",
            "overage": f"${current_cost - max_budget:.4f}",
        }

        suggested_fix = f"Increase budget from ${max_budget:.2f} or wait for reset"

        super().__init__(
            message,
            middleware=middleware,
            tool=tool,
            trace_id=trace_id,
            context=context,
            docs_url="https://docs.agentgate.io/middleware/cost-tracker",
            suggested_fix=suggested_fix,
        )


class ApprovalRequired(AgentSafetyError):
    """Raised when human approval is required.

    This tool requires human approval before execution.
    Approve the request to proceed.
    """

    def __init__(
        self,
        message: str,
        *,
        tool: str,
        inputs: dict[str, Any],
        approval_id: str,
        middleware: str | None = None,
        trace_id: str | None = None,
    ):
        self.tool = tool
        self.inputs = inputs
        self.approval_id = approval_id

        context = {
            "approval_id": approval_id,
            "tool_inputs": str(inputs),
        }

        suggested_fix = f"Approve this request using: agent.approve_request('{approval_id}')"

        super().__init__(
            message,
            middleware=middleware,
            tool=tool,
            trace_id=trace_id,
            context=context,
            docs_url="https://docs.agentgate.io/middleware/human-approval",
            suggested_fix=suggested_fix,
        )


class ApprovalDenied(AgentSafetyError):
    """Raised when human approval is denied.

    A human reviewer has denied this tool execution.
    """

    def __init__(
        self,
        message: str,
        *,
        tool: str,
        denied_by: str | None = None,
        middleware: str | None = None,
        trace_id: str | None = None,
        context: dict[str, Any] | None = None,
    ):
        self.tool = tool
        self.denied_by = denied_by

        ctx = context or {}
        if denied_by:
            ctx["denied_by"] = denied_by

        suggested_fix = "Modify the request or contact the reviewer for details"

        super().__init__(
            message,
            middleware=middleware,
            tool=tool,
            trace_id=trace_id,
            context=ctx,
            docs_url="https://docs.agentgate.io/middleware/human-approval",
            suggested_fix=suggested_fix,
        )


class ApprovalTimeout(AgentSafetyError):
    """Raised when approval request times out.

    The approval request was not reviewed within the timeout period.
    """

    def __init__(
        self,
        message: str,
        *,
        tool: str,
        timeout: float,
        middleware: str | None = None,
        trace_id: str | None = None,
    ):
        self.tool = tool
        self.timeout = timeout

        context = {
            "timeout_seconds": timeout,
        }

        suggested_fix = f"Increase timeout from {timeout}s or respond faster"

        super().__init__(
            message,
            middleware=middleware,
            tool=tool,
            trace_id=trace_id,
            context=context,
            docs_url="https://docs.agentgate.io/middleware/human-approval",
            suggested_fix=suggested_fix,
        )


@dataclass
class TransactionFailed(AgentSafetyError):
    """Raised when a transaction fails and is rolled back."""

    message: str
    failed_step: str
    completed_steps: list[str]
    compensated_steps: list[str]
    traces: list["Trace"]

    def __str__(self) -> str:
        return self.message


class GuardrailViolationError(AgentSafetyError):
    """Raised when a guardrail policy violation occurs.

    The agent attempted an action that violates temporal constraints
    like cooldowns, frequency limits, or state transitions.
    """

    def __init__(
        self,
        message: str,
        *,
        details: dict[str, Any] | None = None,
        middleware: str | None = None,
        tool: str | None = None,
        trace_id: str | None = None,
    ):
        context = dict(details or {})
        self.policy_id = str(context.get("policy_id", ""))
        self.state = str(context.get("current_state", ""))
        self.action = str(context.get("attempted_action", ""))
        self.constraint = context.get("violated_constraint")
        if self.constraint is not None:
            self.constraint = str(self.constraint)

        suggested_fix = "Wait for cooldown period or review policy constraints"
        if self.constraint:
            suggested_fix = f"Constraint violated: {self.constraint}. Review policy rules"

        super().__init__(
            message,
            middleware=middleware,
            tool=tool,
            trace_id=trace_id,
            context=context,
            docs_url="https://docs.agentgate.io/middleware/guardrails",
            suggested_fix=suggested_fix,
        )
