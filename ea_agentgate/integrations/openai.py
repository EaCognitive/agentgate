"""OpenAI SDK integration with agent safety."""

from __future__ import annotations

import json
from importlib import import_module
from types import ModuleType
from typing import Any

from .base import SafeClientBase
from .request_utils import prepare_request_kwargs
from .types import ToolCallResult
from ..agent import Agent

_openai_module: ModuleType | None
try:
    _openai_module = import_module("openai")
except ImportError:
    _openai_module = None


class SafeOpenAI(SafeClientBase):
    """
    OpenAI client wrapper with ea_agentgate.

    Intercepts tool calls and validates them through the agent's middleware.

    Example:
        from ea_agentgate import Agent
        from ea_agentgate.middleware import Validator
        from ea_agentgate.integrations import SafeOpenAI

        agent = Agent(middleware=[Validator(block_paths=["/"])])
        client = SafeOpenAI(agent=agent)

        response = client.chat.completions.create(
            model="gpt-4",
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
        Initialize SafeOpenAI.

        Args:
            agent: Agent instance with middleware configured
            client: Existing OpenAI client (optional)
            **client_kwargs: Arguments passed to OpenAI() if client not provided
        """
        super().__init__(agent=agent)

        if client is not None:
            self._client = client
        else:
            if _openai_module is None:
                raise ImportError(
                    "OpenAI SDK not installed. Install with: pip install ea-agentgate[openai]"
                )
            self._client = _openai_module.OpenAI(**client_kwargs)

    def get_client(self) -> Any:
        """Get the underlying OpenAI client."""
        return self._client

    @property
    def chat(self) -> "_ChatNamespace":
        """Access chat completions API."""
        return _ChatNamespace(self)


class _ChatNamespace:
    """Chat completions namespace."""

    def __init__(self, safe_client: SafeOpenAI):
        self._safe = safe_client

    @property
    def completions(self) -> "_CompletionsNamespace":
        """Access completions API."""
        return _CompletionsNamespace(self._safe)

    def get_client(self) -> Any:
        """Get the underlying OpenAI client."""
        return self._safe.get_client()


class _CompletionsNamespace:
    """Completions namespace."""

    def __init__(self, safe_client: SafeOpenAI):
        self._safe = safe_client

    def create(self, **kwargs: Any) -> Any:
        """
        Create a chat completion with tool call validation.

        All tool calls in the response are validated through the agent's middleware.
        """
        request_kwargs, channel_id, conversation_id = prepare_request_kwargs(
            self._safe,
            kwargs,
            redact_fields=("messages",),
        )

        # Make the actual API call
        client = self._safe.get_client()
        if client is None:
            raise RuntimeError("OpenAI client unavailable")
        response = client.chat.completions.create(**request_kwargs)

        # Extract and validate tool calls
        if hasattr(response, "choices") and response.choices:
            for choice in response.choices:
                self._restore_choice_text(
                    choice,
                    channel_id=channel_id,
                    conversation_id=conversation_id,
                )

                if not hasattr(choice, "message") or not hasattr(choice.message, "tool_calls"):
                    continue
                tool_calls = choice.message.tool_calls or []
                for tc in tool_calls:
                    try:
                        args = json.loads(tc.function.arguments)
                    except (json.JSONDecodeError, AttributeError):
                        args = {}

                    args, _ = self._safe.pii_restore_payload(
                        args,
                        channel_id=channel_id,
                        conversation_id=conversation_id,
                    )

                    result = self._safe.validate_tool_call(tc.function.name, args)
                    result.id = tc.id
                    self._safe.add_tool_call(result)

        return response

    def _restore_choice_text(
        self,
        choice: Any,
        *,
        channel_id: str | None,
        conversation_id: str | None,
    ) -> None:
        """Restore placeholders in OpenAI assistant message text blocks."""
        if not hasattr(choice, "message") or not hasattr(choice.message, "content"):
            return
        content = choice.message.content

        if isinstance(content, str):
            restored_content, _ = self._safe.pii_restore_payload(
                content,
                channel_id=channel_id,
                conversation_id=conversation_id,
            )
            choice.message.content = restored_content
            return

        if isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    restored_text, _ = self._safe.pii_restore_payload(
                        part["text"],
                        channel_id=channel_id,
                        conversation_id=conversation_id,
                    )
                    part["text"] = restored_text
                    continue
                text_value = getattr(part, "text", None)
                if isinstance(text_value, str):
                    restored_text, _ = self._safe.pii_restore_payload(
                        text_value,
                        channel_id=channel_id,
                        conversation_id=conversation_id,
                    )
                    try:
                        setattr(part, "text", restored_text)
                    except (AttributeError, TypeError):
                        continue

    def get_tool_calls(self) -> list[ToolCallResult]:
        """Get tool calls from the last response."""
        return self._safe.get_tool_calls()
