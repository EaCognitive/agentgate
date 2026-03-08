"""
Shared threat detection definitions and enums.

Provides common data structures and enumerations used across threat detection modules.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ThreatSeverity(str, Enum):
    """Severity levels for detected threats."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatType(str, Enum):
    """Types of detected threats."""

    BRUTE_FORCE = "brute_force"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    ROLE_ESCALATION = "role_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    NEW_LOCATION = "new_location"
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    SUSPICIOUS_USER_AGENT = "suspicious_user_agent"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    RATE_LIMIT_ABUSE = "rate_limit_abuse"
    CREDENTIAL_STUFFING = "credential_stuffing"
    ACCOUNT_TAKEOVER = "account_takeover"


@dataclass
class ThreatContext:
    """Context information for a threat event."""

    user_id: int | None = None
    user_email: str | None = None
    endpoint: str | None = None
    user_agent: str | None = None
    action_taken: str | None = None


__all__ = [
    "ThreatSeverity",
    "ThreatType",
    "ThreatContext",
]
