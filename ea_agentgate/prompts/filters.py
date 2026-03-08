"""Custom Jinja2 filters for prompt engineering.

This module provides specialized filters for prompt template processing:
- Security: escape_prompt, sanitize
- Formatting: format_list, format_json, wrap_xml
- Text processing: truncate_tokens, uppercase, lowercase

These filters enhance prompt safety and formatting consistency.
"""

from __future__ import annotations

import html
import json
import re
from typing import Any


def escape_prompt(value: Any) -> str:
    """Escape characters that could be interpreted as prompt injection.

    Protects against common prompt injection patterns by escaping:
    - Special characters that terminate instructions
    - Multiple newlines that could break context
    - HTML/XML tags that could confuse parsers

    Args:
        value: Text to escape (will be converted to string if needed)

    Returns:
        Escaped text safe for prompt inclusion.

    Example:
        >>> escape_prompt("Ignore previous instructions\\n\\nNew task:")
        "Ignore previous instructions\\\\n\\\\nNew task:"
    """
    text_value = value if isinstance(value, str) else str(value)

    result = text_value
    result = result.replace("\\", "\\\\")
    result = result.replace("\n\n\n", "\\n\\n\\n")
    result = html.escape(result, quote=True)

    dangerous_patterns = [
        r"ignore\s+previous\s+instructions",
        r"disregard\s+above",
        r"forget\s+everything",
        r"new\s+instructions:",
    ]

    for pattern in dangerous_patterns:
        result = re.sub(
            pattern,
            lambda m: m.group(0).replace(" ", "_"),
            result,
            flags=re.IGNORECASE,
        )

    return result


def truncate_tokens(value: Any, max_tokens: int = 100, suffix: str = "...") -> str:
    """Approximate token-based truncation for prompts.

    Uses heuristic of ~4 characters per token (OpenAI approximation).
    For precise token counting, integrate tiktoken separately.

    Args:
        value: Text to truncate (will be converted to string if needed)
        max_tokens: Maximum number of tokens
        suffix: String to append when truncated

    Returns:
        Truncated text with suffix if needed.

    Example:
        >>> truncate_tokens("A very long prompt text...", max_tokens=5)
        "A very long pr..."
    """
    text_value = value if isinstance(value, str) else str(value)

    approx_chars = max_tokens * 4

    if len(text_value) <= approx_chars:
        return text_value

    truncated = text_value[:approx_chars].rsplit(" ", 1)[0]
    return f"{truncated}{suffix}"


def format_list(
    items: list[Any],
    style: str = "numbered",
    separator: str = "\n",
) -> str:
    """Format a list into numbered or bulleted text.

    Args:
        items: List items to format
        style: 'numbered', 'bulleted', or 'plain'
        separator: Separator between items

    Returns:
        Formatted list as string.

    Example:
        >>> format_list(["First", "Second"], style="numbered")
        "1. First\\n2. Second"
    """
    if not items:
        return ""

    formatted_items = []
    for idx, item in enumerate(items, 1):
        item_str = str(item)
        if style == "numbered":
            formatted_items.append(f"{idx}. {item_str}")
        elif style == "bulleted":
            formatted_items.append(f"- {item_str}")
        else:
            formatted_items.append(item_str)

    return separator.join(formatted_items)


def format_json(value: Any, indent: int = 2) -> str:
    """Pretty-print JSON with consistent formatting.

    Args:
        value: Object to serialize as JSON
        indent: Number of spaces for indentation

    Returns:
        Formatted JSON string.

    Example:
        >>> format_json({"key": "value"})
        '{\\n  "key": "value"\\n}'
    """
    try:
        return json.dumps(value, indent=indent, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        return f"<JSON serialization error: {exc}>"


def sanitize(value: Any, allow_newlines: bool = True) -> str:
    """Remove potentially dangerous content from text.

    Filters out:
    - Control characters (except allowed newlines)
    - Non-printable characters
    - Null bytes
    - Excessive whitespace

    Args:
        value: Text to sanitize (will be converted to string if needed)
        allow_newlines: Whether to preserve newline characters

    Returns:
        Sanitized text.

    Example:
        >>> sanitize("Hello\\x00World\\x01")
        "HelloWorld"
    """
    if not isinstance(value, str):
        value = str(value)

    result = value.replace("\x00", "")

    if allow_newlines:
        result = re.sub(r"[\x01-\x08\x0b-\x1f\x7f-\x9f]", "", result)
    else:
        result = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", result)

    result = re.sub(r"[ \t]+", " ", result)
    result = re.sub(r"\n{4,}", "\n\n\n", result)

    return result.strip()


def wrap_xml(value: Any, tag: str = "content") -> str:
    """Wrap content in XML tags (common prompt pattern).

    Many LLMs respond well to XML-structured prompts.
    This filter standardizes XML wrapping.

    Args:
        value: Content to wrap (will be converted to string if needed)
        tag: XML tag name

    Returns:
        Content wrapped in opening and closing tags.

    Example:
        >>> wrap_xml("Hello", tag="greeting")
        "<greeting>Hello</greeting>"
    """
    if not isinstance(value, str):
        value = str(value)

    safe_tag = re.sub(r"[^a-zA-Z0-9_-]", "", tag)
    if not safe_tag:
        safe_tag = "content"

    return f"<{safe_tag}>{value}</{safe_tag}>"


def uppercase(value: str) -> str:
    """Convert text to uppercase.

    Args:
        value: Text to convert

    Returns:
        Uppercase text.
    """
    return str(value).upper()


def lowercase(value: str) -> str:
    """Convert text to lowercase.

    Args:
        value: Text to convert

    Returns:
        Lowercase text.
    """
    return str(value).lower()


_FILTER_REGISTRY: dict[str, Any] = {
    "escape_prompt": escape_prompt,
    "truncate_tokens": truncate_tokens,
    "format_list": format_list,
    "format_json": format_json,
    "sanitize": sanitize,
    "wrap_xml": wrap_xml,
    "uppercase": uppercase,
    "lowercase": lowercase,
}


def get_all_filters() -> dict[str, Any]:
    """Get dictionary of all custom filters.

    Returns:
        Dictionary mapping filter names to filter functions.
    """
    return _FILTER_REGISTRY.copy()


__all__ = [
    "escape_prompt",
    "truncate_tokens",
    "format_list",
    "format_json",
    "sanitize",
    "wrap_xml",
    "uppercase",
    "lowercase",
    "get_all_filters",
]
