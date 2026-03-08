"""Base class for LLM provider integrations with tool call validation."""

from __future__ import annotations

from types import ModuleType
from typing import Any

from .types import ToolCallResult
from ..agent import Agent
from ..trace import Trace
from ..exceptions import ValidationError

_middleware_base: ModuleType | None
try:
    from ..middleware import base as _middleware_base
except ImportError:
    _middleware_base = None

MiddlewareContextCls: Any | None = (
    getattr(_middleware_base, "MiddlewareContext", None) if _middleware_base is not None else None
)


class SafeClientBase:
    """
    Base class for LLM client wrappers with ea_agentgate.

    Provides common tool call validation functionality through agent middleware.
    """

    def __init__(self, agent: Agent | None = None):
        """
        Initialize the safe client base.

        Args:
            agent: Agent instance with middleware configured
        """
        self.agent = agent or Agent()
        self._tool_calls: list[ToolCallResult] = []

    def get_tool_calls(self) -> list[ToolCallResult]:
        """Get tool calls from the last response."""
        return self._tool_calls.copy()

    def clear_tool_calls(self) -> None:
        """Clear stored tool calls."""
        self._tool_calls.clear()

    def add_tool_call(self, tool_call: ToolCallResult) -> None:
        """Add a validated tool call to the list.

        Args:
            tool_call: ToolCallResult to add
        """
        self._tool_calls.append(tool_call)

    def pii_redact_payload(
        self,
        payload: Any,
        *,
        channel_id: str | None = None,
        conversation_id: str | None = None,
    ) -> tuple[Any, list[dict[str, Any]]]:
        """Redact payload through PIIVault middleware when configured."""
        pii_middleware = self._get_pii_middleware()
        if pii_middleware is None:
            return payload, []

        redacted, events = pii_middleware.redact_payload(
            payload,
            session_id=self.agent.session_id,
            agent_id=self.agent.agent_id,
            channel_id=channel_id,
            conversation_id=conversation_id,
        )
        return redacted, events

    def pii_restore_payload(
        self,
        payload: Any,
        *,
        channel_id: str | None = None,
        conversation_id: str | None = None,
    ) -> tuple[Any, list[dict[str, Any]]]:
        """Restore payload through PIIVault middleware when configured."""
        pii_middleware = self._get_pii_middleware()
        if pii_middleware is None:
            return payload, []

        restored, events = pii_middleware.restore_payload(
            payload,
            session_id=self.agent.session_id,
            agent_id=self.agent.agent_id,
            channel_id=channel_id,
            conversation_id=conversation_id,
        )
        return restored, events

    def _get_pii_middleware(self) -> Any | None:
        """Find the first middleware that exposes PII redaction hooks."""
        for middleware in self.agent.middleware:
            if (
                hasattr(middleware, "redact_payload")
                and callable(getattr(middleware, "redact_payload"))
                and hasattr(middleware, "restore_payload")
                and callable(getattr(middleware, "restore_payload"))
            ):
                return middleware
        return None

    def validate_tool_call(self, name: str, args: dict[str, Any]) -> ToolCallResult:
        """
        Validate a tool call through the agent's middleware.

        Args:
            name: Name of the tool to validate
            args: Arguments to pass to the tool

        Returns:
            ToolCallResult with blocked=True if validation failed.
        """
        trace = Trace(tool=name, inputs=args)
        trace.start()

        result = ToolCallResult(
            id=trace.id,
            name=name,
            args=args,
            trace=trace,
        )

        try:
            # Run through middleware (before hooks only)
            if MiddlewareContextCls is None:
                raise ImportError("Middleware context not available")

            ctx = MiddlewareContextCls(
                tool=name,
                inputs=args,
                trace=trace,
                agent_id=self.agent.agent_id,
                session_id=self.agent.session_id,
                user_id=self.agent.user_id,
            )

            for mw in self.agent.middleware:
                mw.before(ctx)

            trace.succeed({"validated": True})
        except ValidationError as e:
            result.blocked = True
            result.reason = str(e)
            trace.block(str(e), e.middleware or "unknown")
        except (ImportError, RuntimeError) as e:
            result.blocked = True
            result.reason = str(e)
            trace.fail(str(e))

        self.agent.record_trace(trace)
        return result
