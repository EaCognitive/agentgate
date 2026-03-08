"""
Threat pattern definitions for attack detection.

Provides a comprehensive library of attack patterns including:
- SQL Injection patterns
- XSS (Cross-Site Scripting) patterns
- Path traversal patterns
- Command injection patterns
- LDAP injection patterns
- SSRF patterns
- Header injection patterns

Pattern implementations are organized into category modules:
- ``threat_pattern_base``: Core abstractions
- ``patterns_injection``: Injection-type patterns
- ``patterns_traversal``: Traversal and SSRF patterns

All symbols are re-exported here for full backwards
compatibility.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from collections.abc import Sequence

from .threat_pattern_base import (
    BasePattern,
    PatternMatch,
    PatternSeverity,
    ThreatPattern,
)
from .patterns_injection import (
    CommandInjectionPattern,
    HeaderInjectionPattern,
    LDAPInjectionPattern,
    SQLInjectionPattern,
    XSSPattern,
)
from .patterns_traversal import (
    PathTraversalPattern,
    SSRFPattern,
)


@dataclass
class PatternRegistry:
    """
    Registry for threat patterns with efficient lookup.

    Provides centralized management of all threat patterns
    and supports pattern categorization and filtering.
    """

    _patterns: dict[str, ThreatPattern] = field(default_factory=dict)
    _patterns_by_type: dict[str, list[ThreatPattern]] = field(default_factory=dict)

    def __post_init__(self):
        """Initialize with empty collections."""
        self._patterns = {}
        self._patterns_by_type = {}

    def register(self, pattern: ThreatPattern) -> None:
        """
        Register a threat pattern.

        Args:
            pattern: Pattern to register.
        """
        self._patterns[pattern.name] = pattern

        if pattern.pattern_type not in self._patterns_by_type:
            self._patterns_by_type[pattern.pattern_type] = []

        if pattern not in self._patterns_by_type[pattern.pattern_type]:
            self._patterns_by_type[pattern.pattern_type].append(pattern)

    def unregister(self, name: str) -> bool:
        """
        Unregister a pattern by name.

        Args:
            name: Pattern name to remove.

        Returns:
            True if removed, False if not found.
        """
        if name not in self._patterns:
            return False

        pattern = self._patterns.pop(name)
        if pattern.pattern_type in self._patterns_by_type:
            self._patterns_by_type[pattern.pattern_type] = [
                p for p in self._patterns_by_type[pattern.pattern_type] if p.name != name
            ]
        return True

    def get(self, name: str) -> ThreatPattern | None:
        """Get pattern by name."""
        return self._patterns.get(name)

    def get_by_type(self, pattern_type: str) -> list[ThreatPattern]:
        """Get all patterns of a specific type."""
        return self._patterns_by_type.get(pattern_type, [])

    def all_patterns(self) -> list[ThreatPattern]:
        """Get all registered patterns."""
        return list(self._patterns.values())

    @classmethod
    def create_default(cls) -> PatternRegistry:
        """
        Create registry with all default patterns.

        Returns:
            Registry populated with standard patterns.
        """
        registry = cls()
        registry._patterns = {}
        registry._patterns_by_type = {}

        default_patterns: list[ThreatPattern] = [
            SQLInjectionPattern(),
            XSSPattern(),
            PathTraversalPattern(),
            CommandInjectionPattern(),
            LDAPInjectionPattern(),
            SSRFPattern(),
            HeaderInjectionPattern(),
        ]

        for pattern in default_patterns:
            registry.register(pattern)

        return registry


class PatternMatcher:
    """
    High-performance pattern matcher with caching.

    Provides efficient matching against multiple patterns
    with result aggregation and deduplication.
    """

    def __init__(
        self,
        registry: PatternRegistry | None = None,
        max_matches_per_pattern: int = 5,
        min_confidence: float = 0.0,
    ):
        """
        Initialize pattern matcher.

        Args:
            registry: Pattern registry to use.
            max_matches_per_pattern: Max matches per pattern.
            min_confidence: Minimum confidence threshold.
        """
        self._registry = registry or PatternRegistry.create_default()
        self._max_matches = max_matches_per_pattern
        self._min_confidence = min_confidence

    @property
    def registry(self) -> PatternRegistry:
        """Get the pattern registry."""
        return self._registry

    def match_all(
        self,
        value: str,
        pattern_types: Sequence[str] | None = None,
        severity_filter: (PatternSeverity | None) = None,
    ) -> list[PatternMatch]:
        """
        Match value against all patterns.

        Args:
            value: String to check for threats.
            pattern_types: Optional type filter.
            severity_filter: Optional min severity.

        Returns:
            List of all pattern matches found.
        """
        if not value:
            return []

        matches: list[PatternMatch] = []
        patterns = self._registry.all_patterns()

        if pattern_types:
            patterns = [p for p in patterns if p.pattern_type in pattern_types]

        if severity_filter:
            severity_order = [
                PatternSeverity.LOW,
                PatternSeverity.MEDIUM,
                PatternSeverity.HIGH,
                PatternSeverity.CRITICAL,
            ]
            min_index = severity_order.index(severity_filter)
            patterns = [p for p in patterns if severity_order.index(p.severity) >= min_index]

        for pattern in patterns:
            pattern_matches = pattern.match(value)

            pattern_matches = [m for m in pattern_matches if m.confidence >= self._min_confidence]

            matches.extend(pattern_matches[: self._max_matches])

        severity_rank = {
            PatternSeverity.CRITICAL: 0,
            PatternSeverity.HIGH: 1,
            PatternSeverity.MEDIUM: 2,
            PatternSeverity.LOW: 3,
        }
        matches.sort(
            key=lambda m: (
                severity_rank[m.severity],
                -m.confidence,
            )
        )

        return matches

    def match_type(self, value: str, pattern_type: str) -> list[PatternMatch]:
        """
        Match value against patterns of a specific type.

        Args:
            value: String to check.
            pattern_type: Type of patterns to use.

        Returns:
            List of pattern matches.
        """
        return self.match_all(value, pattern_types=[pattern_type])

    def has_threats(
        self,
        value: str,
        min_severity: PatternSeverity = PatternSeverity.LOW,
    ) -> bool:
        """
        Quick check if value contains any threats.

        Args:
            value: String to check.
            min_severity: Minimum severity to consider.

        Returns:
            True if any threats found.
        """
        matches = self.match_all(value, severity_filter=min_severity)
        return len(matches) > 0

    def get_highest_severity(self, value: str) -> PatternSeverity | None:
        """
        Get the highest severity threat found.

        Args:
            value: String to check.

        Returns:
            Highest severity, or None if no threats.
        """
        matches = self.match_all(value)
        if not matches:
            return None

        severity_order = [
            PatternSeverity.CRITICAL,
            PatternSeverity.HIGH,
            PatternSeverity.MEDIUM,
            PatternSeverity.LOW,
        ]

        for severity in severity_order:
            if any(m.severity == severity for m in matches):
                return severity

        return None


__all__ = [
    "PatternSeverity",
    "PatternMatch",
    "ThreatPattern",
    "BasePattern",
    "SQLInjectionPattern",
    "XSSPattern",
    "PathTraversalPattern",
    "CommandInjectionPattern",
    "LDAPInjectionPattern",
    "SSRFPattern",
    "HeaderInjectionPattern",
    "PatternRegistry",
    "PatternMatcher",
]
