"""Validation middleware for blocking dangerous operations."""

from __future__ import annotations

import fnmatch
import json
import os
import re
import urllib.parse
from dataclasses import dataclass
from typing import Any
from re import Pattern
from collections.abc import Callable

from .base import Middleware, MiddlewareContext
from ..exceptions import ValidationError


@dataclass
class Rule:
    """A validation rule."""

    name: str
    check: Callable[[str, dict[str, Any]], str | None]  # Returns error message or None


class Validator(Middleware):
    """
    Validates tool calls before execution.

    Blocks dangerous operations based on configurable rules.

    Example:
        validator = Validator(
            block_paths=["/", "C:/", "/etc"],
            block_patterns=["rm -rf", "DROP TABLE"],
            block_tools=["delete_database"],
        )
    """

    # Default dangerous paths
    DEFAULT_BLOCKED_PATHS = [
        "/",
        "/etc",
        "/usr",
        "/var",
        "/bin",
        "/sbin",
        "/root",
        "/home",
        "C:/",
        "C:\\",
        "C:/Windows",
        "D:/",
        "D:\\",
    ]

    # Default dangerous patterns
    DEFAULT_BLOCKED_PATTERNS = [
        "rm -rf",
        "--no-preserve-root",
        ":(){ :|:& };:",
        "mkfs",
        "dd if=",
        "> /dev/sd",
        "DROP TABLE",
        "DROP DATABASE",
        "DELETE FROM",
        "TRUNCATE",
        "; --",
        "' OR '1'='1",
        "<script>",
        "javascript:",
        "../../",
    ]

    def __init__(
        self,
        *,
        block_paths: list[str] | None = None,
        block_patterns: list[str] | None = None,
        block_tools: list[str] | None = None,
        allow_tools: list[str] | None = None,
        custom_rules: list[Rule] | None = None,
        use_defaults: bool = True,
    ):
        """
        Initialize validator.

        Args:
            block_paths: Filesystem paths to block
            block_patterns: String patterns to block (checked in all params)
            block_tools: Tool names to block (supports wildcards like "delete_*")
            allow_tools: If set, only these tools are allowed
            custom_rules: Custom validation rules
            use_defaults: Include default blocked paths/patterns
        """
        super().__init__()
        self.block_paths: list[str] = []
        self.block_patterns: list[str] = []
        self.block_tools = block_tools or []
        self.allow_tools = allow_tools
        self.custom_rules = custom_rules or []

        if use_defaults:
            self.block_paths.extend(self.DEFAULT_BLOCKED_PATHS)
            self.block_patterns.extend(self.DEFAULT_BLOCKED_PATTERNS)

        if block_paths:
            self.block_paths.extend(block_paths)
        if block_patterns:
            self.block_patterns.extend(block_patterns)

        # Compile patterns for efficiency
        self._pattern_regexes: list[Pattern[str]] = [
            re.compile(re.escape(p), re.IGNORECASE) for p in self.block_patterns
        ]

    def before(self, ctx: MiddlewareContext) -> None:
        """Validate tool call before execution."""
        tool = ctx.tool
        inputs = ctx.inputs

        # Check allow list
        if self.allow_tools is not None:
            allowed = any(fnmatch.fnmatch(tool, pattern) for pattern in self.allow_tools)
            if not allowed:
                ctx.trace.block(f"Tool '{tool}' is not in allow list", self.name)
                raise ValidationError(
                    f"Tool '{tool}' is not in allow list",
                    middleware=self.name,
                    tool=tool,
                    trace_id=ctx.trace.id,
                    context={"allow_list": self.allow_tools},
                    suggested_fix=f"Add '{tool}' to allow_tools or use an allowed tool",
                )

        # Check block list
        for pattern in self.block_tools:
            if fnmatch.fnmatch(tool, pattern):
                ctx.trace.block(f"Tool '{tool}' is blocked", self.name)
                raise ValidationError(
                    f"Tool '{tool}' is blocked",
                    middleware=self.name,
                    tool=tool,
                    trace_id=ctx.trace.id,
                    context={"blocked_pattern": pattern},
                    suggested_fix=f"Remove '{tool}' from block_tools or use a different tool",
                )

        # Check paths in inputs
        self._check_paths(ctx)

        # Check patterns in inputs
        self._check_patterns(ctx)

        # Run custom rules
        for rule in self.custom_rules:
            error = rule.check(tool, inputs)
            if error:
                ctx.trace.block(f"Custom rule violation: {rule.name}", self.name)
                raise ValidationError(
                    error,
                    middleware=self.name,
                    tool=tool,
                    trace_id=ctx.trace.id,
                    context={"rule": rule.name},
                    suggested_fix="Review custom validation rule requirements",
                )

    @staticmethod
    def _decode_path(value: str) -> str:
        """Decode URL-encoded sequences and normalize path separators."""
        decoded = urllib.parse.unquote(value)
        decoded = decoded.replace("\\", "/")
        return decoded

    @staticmethod
    def _resolve_canonical(path: str) -> str:
        """Resolve a path to its canonical form using os.path.realpath.

        This collapses all traversal sequences (../, ./, symlinks) into a
        single absolute path, neutralizing obfuscation attempts.
        """
        return os.path.realpath(path)

    def _check_paths(self, ctx: MiddlewareContext) -> None:
        """Check for dangerous paths in inputs.

        Uses canonical path resolution (os.path.realpath) to defeat obfuscated
        traversal attacks such as URL-encoded sequences, double-dot chains,
        and mixed separators. Paths are resolved to their absolute canonical
        form before comparison against blocked paths.
        """
        for value in ctx.inputs.values():
            if not isinstance(value, str):
                continue

            # Decode URL-encoded sequences before resolution
            decoded = self._decode_path(value)

            # Resolve to canonical absolute path, collapsing ../ sequences
            canonical = self._resolve_canonical(decoded)
            canonical_lower = canonical.lower()

            for blocked in self.block_paths:
                blocked_canonical = self._resolve_canonical(self._decode_path(blocked))
                blocked_lower = blocked_canonical.lower()

                # Exact match against canonical paths
                if canonical_lower == blocked_lower:
                    ctx.trace.block(f"Blocked path: '{value}'", self.name)
                    raise ValidationError(
                        f"Blocked path: '{value}' resolves to protected path '{blocked}'",
                        middleware=self.name,
                        tool=ctx.tool,
                        trace_id=ctx.trace.id,
                        context={
                            "blocked_path": value,
                            "canonical_path": canonical,
                            "protected_path": blocked,
                        },
                        suggested_fix="Use a safe path outside blocked directories",
                    )

                # Check if the canonical path falls under a blocked directory
                # Use os.path.commonpath for reliable prefix comparison
                try:
                    common = os.path.commonpath([canonical, blocked_canonical])
                    if common.lower() == blocked_lower and canonical_lower != blocked_lower:
                        ctx.trace.block(f"Blocked path: '{value}'", self.name)
                        raise ValidationError(
                            f"Blocked path: '{value}' resolves under protected path '{blocked}'",
                            middleware=self.name,
                            tool=ctx.tool,
                            trace_id=ctx.trace.id,
                            context={
                                "blocked_path": value,
                                "canonical_path": canonical,
                                "protected_directory": blocked,
                            },
                            suggested_fix="Use a path outside blocked directories",
                        )
                except ValueError:
                    # commonpath raises ValueError for paths on different drives (Windows)
                    pass

    @staticmethod
    def _normalize_whitespace(text: str) -> str:
        """Collapse all whitespace sequences to single spaces.

        Defeats obfuscation via double spaces, tabs, or mixed whitespace
        characters (e.g., "rm  -rf" or "DROP\\tTABLE").
        """
        return re.sub(r"\s+", " ", text)

    def _check_patterns(self, ctx: MiddlewareContext) -> None:
        """Check for dangerous patterns in inputs.

        Normalizes whitespace and decodes URL-encoded sequences before
        matching, defeating common obfuscation techniques.
        """
        inputs_str = json.dumps(ctx.inputs)

        # Also check URL-decoded and whitespace-normalized variants
        decoded_str = urllib.parse.unquote(inputs_str)
        normalized_str = self._normalize_whitespace(decoded_str)

        for i, regex in enumerate(self._pattern_regexes):
            if regex.search(inputs_str) or regex.search(normalized_str):
                pattern = self.block_patterns[i]
                ctx.trace.block(f"Blocked pattern: '{pattern}'", self.name)
                raise ValidationError(
                    f"Blocked pattern detected: '{pattern}'",
                    middleware=self.name,
                    tool=ctx.tool,
                    trace_id=ctx.trace.id,
                    context={"blocked_pattern": pattern},
                    suggested_fix=f"Remove dangerous pattern '{pattern}' from inputs",
                )
