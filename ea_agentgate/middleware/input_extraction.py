"""Shared helpers for extracting common middleware inputs."""

from __future__ import annotations

from typing import Any


def extract_prompt_text(inputs: dict[str, Any]) -> str:
    """Extract the most relevant prompt-like text from tool inputs."""
    if "prompt" in inputs:
        return str(inputs["prompt"])
    if "text" in inputs:
        return str(inputs["text"])
    if "message" in inputs:
        return str(inputs["message"])
    if "messages" in inputs and isinstance(inputs["messages"], list):
        if inputs["messages"] and isinstance(inputs["messages"][-1], dict):
            if "content" in inputs["messages"][-1]:
                return str(inputs["messages"][-1]["content"])
    return ""
