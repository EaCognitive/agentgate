"""Pydantic models for structured MCP resource and tool output."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ThreatSummary(BaseModel):
    """Summary of a single threat event for MCP resources."""

    id: int
    event_id: str
    event_type: str
    severity: str | None = None
    status: str
    source_ip: str | None = None
    target: str | None = None
    description: str | None = None
    detected_at: datetime
    user_email: str | None = None


class ThreatStatsResponse(BaseModel):
    """Aggregated threat statistics."""

    total_threats: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    resolved: int = 0
    pending: int = 0
    trend: int = 0
    period_hours: int = 24


class TimelineBucket(BaseModel):
    """Single hourly bucket in threat timeline."""

    timestamp: str
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class BlockedIPDetail(BaseModel):
    """Details about a blocked IP address."""

    ip: str
    reason: str
    expires_at: float
    remaining_seconds: float = Field(description="Seconds until block expires")


class DetectorStatsResponse(BaseModel):
    """Detection engine statistics."""

    total_checks: int = 0
    threats_detected: int = 0
    ips_blocked: int = 0
    brute_force_detected: int = 0
    injection_detected: int = 0


class AlertStatsResponse(BaseModel):
    """Alert manager statistics."""

    total_sent: int = 0
    total_suppressed: int = 0
    total_deduplicated: int = 0
    channels_configured: int = 0


class PreviewTokenResponse(BaseModel):
    """Response containing a signed preview token for destructive actions."""

    action: str
    preview: dict[str, Any]
    preview_token: str
    expires_in_seconds: int = 300
    message: str = "Review the preview and confirm with the token."


class ActionConfirmedResponse(BaseModel):
    """Response after a confirmed destructive action."""

    action: str
    success: bool
    detail: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class RiskScore(BaseModel):
    """AI risk scorer result."""

    score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str
    recommended_action: str
    provider: str = "none"
    timed_out: bool = False


class RedTeamResult(BaseModel):
    """Red-team payload generation and testing result."""

    category: str
    total_payloads: int
    detected_count: int
    missed_count: int
    detection_rate: float
    missed_payloads: list[str] = Field(default_factory=list)


class RedTeamReport(BaseModel):
    """Aggregate red-team detection report."""

    categories: list[RedTeamResult]
    global_total: int
    global_detected: int
    global_detection_rate: float
    warnings: list[str] = Field(default_factory=list)


class PolicyDiff(BaseModel):
    """Diff between current and proposed policy."""

    added_rules: list[dict[str, Any]] = Field(default_factory=list)
    removed_rules: list[dict[str, Any]] = Field(default_factory=list)
    modified_rules: list[dict[str, Any]] = Field(default_factory=list)
    summary: str = ""


class ParsedPolicy(BaseModel):
    """Result of parsing natural language into structured policy."""

    policy_json: dict[str, Any]
    diff: PolicyDiff
    confidence: float = Field(ge=0.0, le=1.0)
    warnings: list[str] = Field(default_factory=list)


class PolicySimulationResult(BaseModel):
    """Result of simulating policy rules against test inputs."""

    total_inputs: int
    blocked_count: int
    allowed_count: int
    escalated_count: int
    results: list[dict[str, Any]] = Field(default_factory=list)
