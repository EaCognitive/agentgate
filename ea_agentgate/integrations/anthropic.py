"""Anthropic SDK integration with agent safety."""

from __future__ import annotations

from importlib import import_module
from types import ModuleType
from typing import Any

from .base import SafeClientBase
from .request_utils import prepare_request_kwargs
from .types import ToolCallResult
from ..agent import Agent

_anthropic_module: ModuleType | None
try:
    _anthropic_module = import_module("anthropic")
except ImportError:
    _anthropic_module = None


class SafeAnthropic(SafeClientBase):
    """
    Anthropic client wrapper with ea_agentgate.

    Intercepts tool calls and validates them through the agent's middleware.

    Example:
        from ea_agentgate import Agent
        from ea_agentgate.middleware import Validator
        from ea_agentgate.integrations import SafeAnthropic

        agent = Agent(middleware=[Validator(block_paths=["/"])])
        client = SafeAnthropic(agent=agent)

        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            messages=[...],
            tools=[...]
        )

        # Check which tool calls were blocked
        for call in client.get_tool_calls():
            if call.blocked:
                print(f"Blocked: {call.name} - {call.reason}")
    """

    def __init__(
        self,
        agent: Agent | None = None,
        client: Any | None = None,
        **client_kwargs: Any,
    ):
        """
        Initialize SafeAnthropic.

        Args:
            agent: Agent instance with middleware configured
            client: Existing Anthropic client (optional)
            **client_kwargs: Arguments passed to Anthropic() if client not provided
        """
        super().__init__(agent=agent)

        if client is not None:
            self._client = client
        else:
            if _anthropic_module is None:
                raise ImportError(
                    "Anthropic SDK not installed. Install with: pip install ea-agentgate[anthropic]"
                )
            self._client = _anthropic_module.Anthropic(**client_kwargs)

    def get_client(self) -> Any:
        """Get the underlying Anthropic client."""
        return self._client

    @property
    def messages(self) -> "_MessagesNamespace":
        """Access messages API."""
        return _MessagesNamespace(self)


class _MessagesNamespace:
    """Messages namespace."""

    def __init__(self, safe_client: SafeAnthropic):
        self._safe = safe_client

    def create(self, **kwargs: Any) -> Any:
        """
        Create a message with tool call validation.

        All tool calls in the response are validated through the agent's middleware.
        """
        request_kwargs, channel_id, conversation_id = prepare_request_kwargs(
            self._safe,
            kwargs,
            redact_fields=("messages", "system"),
        )

        # Make the actual API call
        client = self._safe.get_client()
        if client is None:
            raise RuntimeError("Anthropic client unavailable")
        response = client.messages.create(**request_kwargs)

        # Extract and validate tool calls
        if hasattr(response, "content"):
            for block in response.content:
                if getattr(block, "type", None) == "text":
                    text_value = getattr(block, "text", None)
                    if isinstance(text_value, str):
                        restored_text, _ = self._safe.pii_restore_payload(
                            text_value,
                            channel_id=channel_id,
                            conversation_id=conversation_id,
                        )
                        try:
                            setattr(block, "text", restored_text)
                        except (AttributeError, TypeError):
                            pass
                if getattr(block, "type", None) == "tool_use":
                    name = getattr(block, "name", "unknown")
                    args = getattr(block, "input", {})
                    block_id = getattr(block, "id", "")
                    args, _ = self._safe.pii_restore_payload(
                        args,
                        channel_id=channel_id,
                        conversation_id=conversation_id,
                    )

                    result = self._safe.validate_tool_call(name, args)
                    result.id = block_id
                    self._safe.add_tool_call(result)

        return response

    def get_tool_calls(self) -> list[ToolCallResult]:
        """Get tool calls from the last response."""
        return self._safe.get_tool_calls()
