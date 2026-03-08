"""
Base classes and protocols for threat pattern definitions.

Provides:
- PatternSeverity: Severity levels for pattern matches
- PatternMatch: Result of a pattern match operation
- ThreatPattern: Protocol for pattern implementations
- BasePattern: Abstract base class for regex-based patterns
"""

from __future__ import annotations

import re
from abc import ABC
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol


class PatternSeverity(str, Enum):
    """Severity levels for pattern matches."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class PatternMatch:
    """Result of a pattern match operation."""

    pattern_name: str
    pattern_type: str
    severity: PatternSeverity
    matched_value: str
    position: int
    context: str
    confidence: float  # 0.0 to 1.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "pattern_name": self.pattern_name,
            "pattern_type": self.pattern_type,
            "severity": self.severity.value,
            "matched_value": self.matched_value,
            "position": self.position,
            "context": self.context,
            "confidence": self.confidence,
        }


class ThreatPattern(Protocol):
    """Protocol for threat pattern implementations."""

    @property
    def name(self) -> str:
        """Pattern identifier."""
        raise NotImplementedError

    @property
    def pattern_type(self) -> str:
        """Category of threat pattern."""
        raise NotImplementedError

    @property
    def severity(self) -> PatternSeverity:
        """Default severity for this pattern."""
        raise NotImplementedError

    def match(self, value: str) -> list[PatternMatch]:
        """
        Check if value matches this threat pattern.

        Args:
            value: The input string to check.

        Returns:
            List of PatternMatch objects found.
        """
        raise NotImplementedError


class BasePattern(ABC):
    """Abstract base class for threat patterns."""

    def __init__(
        self,
        name: str,
        pattern_type: str,
        severity: PatternSeverity,
        patterns: list[str],
        *,
        flags: int = re.IGNORECASE,
        confidence: float = 0.9,
    ):
        """
        Initialize base pattern.

        Args:
            name: Pattern identifier.
            pattern_type: Category of threat.
            severity: Default severity level.
            patterns: List of regex patterns to match.
            flags: Regex flags to apply.
            confidence: Default confidence score.
        """
        self._name = name
        self._pattern_type = pattern_type
        self._severity = severity
        self._confidence = confidence
        self._compiled_patterns: list[re.Pattern[str]] = [re.compile(p, flags) for p in patterns]

    @property
    def name(self) -> str:
        """Get the pattern name."""
        return self._name

    @property
    def pattern_type(self) -> str:
        """Get the pattern type."""
        return self._pattern_type

    @property
    def severity(self) -> PatternSeverity:
        """Get the pattern severity."""
        return self._severity

    def match(self, value: str) -> list[PatternMatch]:
        """Check if value matches any pattern."""
        matches: list[PatternMatch] = []

        for pattern in self._compiled_patterns:
            for found in pattern.finditer(value):
                start = max(0, found.start() - 20)
                end = min(len(value), found.end() + 20)
                context = value[start:end]

                matches.append(
                    PatternMatch(
                        pattern_name=self._name,
                        pattern_type=(self._pattern_type),
                        severity=self._severity,
                        matched_value=found.group(),
                        position=found.start(),
                        context=context,
                        confidence=self._confidence,
                    )
                )

        return matches


__all__ = [
    "PatternSeverity",
    "PatternMatch",
    "ThreatPattern",
    "BasePattern",
]
