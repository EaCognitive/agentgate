"""Prompt engineering and template management module.

This module provides sophisticated prompt engineering capabilities
including template management, variable substitution, and creative
steering techniques for LLM interactions.
"""

from .registry import (
    get_pii_detection_prompt,
    get_semantic_prompt,
    load_prompt_registry,
)
from .manager import (
    Jinja2TemplateEngine,
    PromptTemplateManager,
    ChainOfThoughtPrompt,
    FewShotPrompt,
    RolePrompt,
)
from .filters import (
    escape_prompt,
    truncate_tokens,
    format_list,
    format_json,
    sanitize,
    wrap_xml,
    get_all_filters,
)

__all__ = [
    "load_prompt_registry",
    "get_semantic_prompt",
    "get_pii_detection_prompt",
    "Jinja2TemplateEngine",
    "PromptTemplateManager",
    "ChainOfThoughtPrompt",
    "FewShotPrompt",
    "RolePrompt",
    "escape_prompt",
    "truncate_tokens",
    "format_list",
    "format_json",
    "sanitize",
    "wrap_xml",
    "get_all_filters",
]
