"""Shared helpers for safe SDK integration request handling."""

from __future__ import annotations

from typing import Any


def prepare_request_kwargs(
    safe_client: Any,
    kwargs: dict[str, Any],
    *,
    redact_fields: tuple[str, ...],
) -> tuple[dict[str, Any], str | None, str | None]:
    """Prepare request kwargs and redact configured payload fields."""
    safe_client.clear_tool_calls()
    request_kwargs = dict(kwargs)
    channel_id = request_kwargs.get("channel_id")
    conversation_id = request_kwargs.get("conversation_id")

    for field_name in redact_fields:
        if field_name not in request_kwargs:
            continue
        redacted_payload, _ = safe_client.pii_redact_payload(
            request_kwargs[field_name],
            channel_id=channel_id,
            conversation_id=conversation_id,
        )
        request_kwargs[field_name] = redacted_payload

    return request_kwargs, channel_id, conversation_id
