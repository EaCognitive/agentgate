"""
Injection-type threat pattern definitions.

Provides pattern classes for detecting:
- SQL Injection attacks
- Cross-Site Scripting (XSS)
- Command injection
- LDAP injection
- HTTP header injection
"""

from __future__ import annotations

from .threat_pattern_base import BasePattern, PatternSeverity


class SQLInjectionPattern(BasePattern):
    """SQL injection attack patterns."""

    SQL_PATTERNS = [
        # Union-based injection
        r"(?:union\s+(?:all\s+)?select)",
        r"(?:select\s+.*\s+from\s+)",
        # Comment-based injection
        r"(?:--|#|/\*|\*/)",
        # Boolean-based injection
        r"(?:'\s*(?:or|and)\s*'?\d*'?\s*[=<>])",
        r"(?:\bor\b\s+\d+\s*=\s*\d+)",
        r"(?:\band\b\s+\d+\s*=\s*\d+)",
        # Time-based injection
        r"(?:sleep\s*\(\s*\d+\s*\))",
        r"(?:benchmark\s*\(\s*\d+)",
        r"(?:waitfor\s+delay)",
        # Stacked queries
        r"(?:;\s*(?:drop|delete|update|insert|create|alter|exec))",
        # Common SQL keywords in suspicious context
        r"(?:';\s*--)",
        r"(?:'\s*;\s*drop\s+)",
        r"(?:1\s*=\s*1)",
        r"(?:'\s*=\s*')",
        # Information gathering
        r"(?:information_schema)",
        r"(?:sys(?:\.|\s+)(?:databases|tables|columns))",
        # DBMS-specific
        r"(?:pg_sleep|mysql\.user|sqlite_master)",
    ]

    def __init__(self):
        """Initialize SQL injection pattern matcher."""
        super().__init__(
            name="sql_injection",
            pattern_type="injection",
            severity=PatternSeverity.CRITICAL,
            patterns=self.SQL_PATTERNS,
            confidence=0.85,
        )


class XSSPattern(BasePattern):
    """Cross-site scripting attack patterns."""

    XSS_PATTERNS = [
        # Script tags
        r"<\s*script[^>]*>",
        r"</\s*script\s*>",
        # Event handlers
        r"(?:on(?:load|error|click|mouse|focus|blur"
        r"|key|submit|change|input))\s*=",
        # JavaScript protocol
        r"javascript\s*:",
        r"vbscript\s*:",
        r"data\s*:\s*text/html",
        # DOM manipulation
        r"document\s*\.\s*(?:cookie|location|write|domain)",
        r"window\s*\.\s*(?:location|open|eval)",
        # Encoded payloads
        r"(?:&#x?[0-9a-f]+;?)+",
        r"(?:%[0-9a-f]{2})+script",
        # SVG-based XSS
        r"<\s*svg[^>]*\s+on\w+\s*=",
        r"<\s*svg[^>]*>.*?<\s*script",
        # IMG-based XSS
        r"<\s*img[^>]*\s+on\w+\s*=",
        # Iframe injection
        r"<\s*iframe[^>]*>",
        # Style-based XSS
        r"expression\s*\(",
        r"url\s*\(\s*['\"]?\s*javascript:",
        # Template injection
        r"\{\{.*?\}\}",
        r"\$\{.*?\}",
    ]

    def __init__(self):
        """Initialize XSS pattern matcher."""
        super().__init__(
            name="xss",
            pattern_type="injection",
            severity=PatternSeverity.HIGH,
            patterns=self.XSS_PATTERNS,
            confidence=0.80,
        )


class CommandInjectionPattern(BasePattern):
    """Command injection attack patterns."""

    CMD_PATTERNS = [
        # Shell metacharacters
        r"(?:[;&|]{2,})|(?:[`$]\()|(?:;\s*[a-z]+)",
        r"(?:\$\([^)]+\))",
        r"(?:`[^`]+`)",
        # Common commands
        r"(?:\b(?:cat|ls|dir|type|wget|curl|nc|netcat)\b)",
        r"(?:\b(?:rm|del|rmdir|rd)\s+[-/])",
        r"(?:\b(?:chmod|chown|sudo|su)\b)",
        # Piping and redirection
        r"(?:[|]{1,2})",
        r"(?:>\s*/)",
        r"(?:>>\s*/)",
        # Shell-specific
        r"(?:/bin/(?:sh|bash|zsh|csh|ksh))",
        r"(?:cmd\.exe|powershell)",
        # Reverse shells
        r"(?:bash\s+-i)",
        r"(?:/dev/tcp/)",
        r"(?:mkfifo)",
        # Encoded
        r"(?:\$IFS)",
        r"(?:\\x[0-9a-f]{2})",
    ]

    def __init__(self):
        """Initialize command injection pattern matcher."""
        super().__init__(
            name="command_injection",
            pattern_type="injection",
            severity=PatternSeverity.CRITICAL,
            patterns=self.CMD_PATTERNS,
            confidence=0.75,
        )


class LDAPInjectionPattern(BasePattern):
    """LDAP injection attack patterns."""

    LDAP_PATTERNS = [
        # LDAP operators
        r"(?:\)\s*[|&!]\s*\()",
        r"(?:\*\s*\)\s*\()",
        # Common injections
        r"(?:\)\s*\(\|\s*\()",
        r"(?:\)\s*\(&\s*\()",
        # Wildcard abuse
        r"(?:\*{2,})",
        # Null character
        r"(?:%00|\x00)",
        # Distinguished name manipulation
        r"(?:(?:cn|uid|ou|dc)\s*=\s*\*)",
    ]

    def __init__(self):
        """Initialize LDAP injection pattern matcher."""
        super().__init__(
            name="ldap_injection",
            pattern_type="injection",
            severity=PatternSeverity.HIGH,
            patterns=self.LDAP_PATTERNS,
            confidence=0.80,
        )


class HeaderInjectionPattern(BasePattern):
    """HTTP header injection attack patterns."""

    HEADER_PATTERNS = [
        # CRLF injection
        r"(?:%0d%0a|\r\n|\n)",
        r"(?:%0d|\r)",
        r"(?:%0a|\n)",
        # Header manipulation
        r"(?:Set-Cookie:)",
        r"(?:Location:)",
        r"(?:Content-Type:)",
        r"(?:X-Forwarded-For:)",
        # Response splitting
        r"(?:HTTP/\d\.\d\s+\d{3})",
    ]

    def __init__(self):
        """Initialize header injection pattern matcher."""
        super().__init__(
            name="header_injection",
            pattern_type="injection",
            severity=PatternSeverity.MEDIUM,
            patterns=self.HEADER_PATTERNS,
            confidence=0.75,
        )


__all__ = [
    "SQLInjectionPattern",
    "XSSPattern",
    "CommandInjectionPattern",
    "LDAPInjectionPattern",
    "HeaderInjectionPattern",
]
