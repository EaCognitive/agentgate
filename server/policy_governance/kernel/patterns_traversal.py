"""
Traversal and SSRF threat pattern definitions.

Provides pattern classes for detecting:
- Path traversal attacks
- Server-Side Request Forgery (SSRF) attacks
"""

from __future__ import annotations

from .threat_pattern_base import BasePattern, PatternSeverity


class PathTraversalPattern(BasePattern):
    """Path traversal attack patterns."""

    PATH_PATTERNS = [
        # Directory traversal
        r"(?:\.\./){2,}",
        r"(?:\.\.\\){2,}",
        r"(?:%2e%2e[/%5c])+",
        r"(?:%252e%252e[/%255c])+",
        # Absolute paths
        r"(?:/etc/(?:passwd|shadow|hosts|group))",
        r"(?:/proc/(?:self|version|cpuinfo))",
        r"(?:/var/(?:log|www|mail))",
        r"(?:c:\\windows\\system32)",
        r"(?:c:/windows/system32)",
        # Null byte injection
        r"(?:%00|\\x00)",
        # Windows-specific
        r"(?:\\\\[a-z]+\\[a-z$]+)",
        r"(?:file://)",
        # Sensitive files
        r"(?:\.htaccess|\.htpasswd|web\.config)",
        r"(?:wp-config\.php|config\.php|settings\.py)",
    ]

    def __init__(self):
        """Initialize path traversal pattern matcher."""
        super().__init__(
            name="path_traversal",
            pattern_type="traversal",
            severity=PatternSeverity.HIGH,
            patterns=self.PATH_PATTERNS,
            confidence=0.85,
        )


class SSRFPattern(BasePattern):
    """Server-Side Request Forgery attack patterns."""

    SSRF_PATTERNS = [
        # Internal addresses
        r"(?:127\.0\.0\.\d+)",
        r"(?:0\.0\.0\.0)",
        r"(?:localhost)",
        r"(?:::1)",
        # Private IP ranges
        r"(?:10\.\d+\.\d+\.\d+)",
        r"(?:172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)",
        r"(?:192\.168\.\d+\.\d+)",
        # Cloud metadata endpoints
        r"(?:169\.254\.169\.254)",
        r"(?:metadata\.google)",
        r"(?:metadata\.aws)",
        # File protocol
        r"(?:file://)",
        r"(?:gopher://)",
        r"(?:dict://)",
        # DNS rebinding patterns
        r"(?:\d+\.\d+\.\d+\.\d+\.xip\.io)",
        r"(?:nip\.io)",
    ]

    def __init__(self):
        """Initialize SSRF pattern matcher."""
        super().__init__(
            name="ssrf",
            pattern_type="ssrf",
            severity=PatternSeverity.HIGH,
            patterns=self.SSRF_PATTERNS,
            confidence=0.70,
        )


__all__ = [
    "PathTraversalPattern",
    "SSRFPattern",
]
