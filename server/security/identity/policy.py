"""Risk model and policy decision evaluation helpers."""

from __future__ import annotations

from collections.abc import Iterable

from server.models import (
    AuthorizationContext,
    PolicyDecision,
    ActionSensitivityLevel,
    PrincipalRiskLevel,
    RuntimeThreatLevel,
    SessionAssuranceLevel,
)

RISK_ORDER = {
    "R0": 0,
    "R1": 1,
    "R2": 2,
    "R3": 3,
    "R4": 4,
}

ASSURANCE_ORDER = {
    "A1": 1,
    "A2": 2,
    "A3": 3,
}

SENSITIVITY_TO_RISK = {
    ActionSensitivityLevel.S0.value: "R0",
    ActionSensitivityLevel.S1.value: "R1",
    ActionSensitivityLevel.S2.value: "R2",
    ActionSensitivityLevel.S3.value: "R3",
    ActionSensitivityLevel.S4.value: "R4",
}

THREAT_TO_RISK = {
    RuntimeThreatLevel.T0.value: "R0",
    RuntimeThreatLevel.T1.value: "R1",
    RuntimeThreatLevel.T2.value: "R2",
    RuntimeThreatLevel.T3.value: "R3",
    RuntimeThreatLevel.T4.value: "R4",
}


def normalize_risk_level(value: str | None) -> str:
    """Normalize a risk level string to supported range."""
    normalized = (value or PrincipalRiskLevel.R1.value).strip().upper()
    if normalized not in RISK_ORDER:
        return PrincipalRiskLevel.R1.value
    return normalized


def normalize_assurance_level(value: str | None) -> str:
    """Normalize an assurance level string to supported range."""
    normalized = (value or SessionAssuranceLevel.A1.value).strip().upper()
    if normalized not in ASSURANCE_ORDER:
        return SessionAssuranceLevel.A1.value
    return normalized


def _max_risk(risks: Iterable[str]) -> str:
    normalized = [normalize_risk_level(level) for level in risks]
    normalized.sort(key=lambda level: RISK_ORDER[level], reverse=True)
    return normalized[0] if normalized else PrincipalRiskLevel.R1.value


def required_assurance_for_risk(risk_level: str) -> str:
    """Map effective risk to minimum required assurance."""
    normalized = normalize_risk_level(risk_level)
    if normalized in {"R0", "R1"}:
        return "A1"
    if normalized == "R2":
        return "A2"
    if normalized == "R3":
        return "A2"
    return "A3"


def _is_assurance_sufficient(current: str, required: str) -> bool:
    return (
        ASSURANCE_ORDER[normalize_assurance_level(current)]
        >= ASSURANCE_ORDER[normalize_assurance_level(required)]
    )


def evaluate_policy_decision(
    *,
    context: AuthorizationContext,
    action: str,
    resource: str,
    action_sensitivity: str = ActionSensitivityLevel.S2.value,
    runtime_threat: str = RuntimeThreatLevel.T0.value,
) -> PolicyDecision:
    """Evaluate authorization decision from context and risk dimensions."""
    _ = action
    _ = resource
    principal_risk = normalize_risk_level(context.principal_risk)
    mapped_sensitivity = SENSITIVITY_TO_RISK.get(
        (action_sensitivity or ActionSensitivityLevel.S2.value).strip().upper(),
        "R2",
    )
    mapped_threat = THREAT_TO_RISK.get(
        (runtime_threat or RuntimeThreatLevel.T0.value).strip().upper(),
        "R0",
    )
    effective_risk = _max_risk([principal_risk, mapped_sensitivity, mapped_threat])
    required_assurance = required_assurance_for_risk(effective_risk)
    session_assurance = normalize_assurance_level(context.session_assurance)

    obligations: list[str] = []
    required_step_up = effective_risk in {"R3", "R4"} and session_assurance != "A3"
    required_approval = effective_risk in {"R3", "R4"}
    if required_step_up:
        obligations.append("step_up_auth")
    if required_approval:
        obligations.append("human_approval")
    if effective_risk == "R4":
        obligations.append("dual_control")

    if not context.roles:
        return PolicyDecision(
            allowed=False,
            reason="No roles available in authorization context",
            required_step_up=required_step_up,
            required_approval=required_approval,
            obligations=obligations,
            decision_id="",
            effective_risk=effective_risk,
            required_assurance=required_assurance,
            session_assurance=session_assurance,
        )

    normalized_roles = {role.strip().lower() for role in context.roles}
    if "viewer" in normalized_roles and effective_risk in {"R2", "R3", "R4"}:
        return PolicyDecision(
            allowed=False,
            reason="Viewer role is restricted from medium/high risk operations",
            required_step_up=required_step_up,
            required_approval=required_approval,
            obligations=obligations,
            decision_id="",
            effective_risk=effective_risk,
            required_assurance=required_assurance,
            session_assurance=session_assurance,
        )

    if not _is_assurance_sufficient(session_assurance, required_assurance):
        return PolicyDecision(
            allowed=False,
            reason=(
                f"Session assurance {session_assurance} does not satisfy "
                f"required level {required_assurance}"
            ),
            required_step_up=True,
            required_approval=required_approval,
            obligations=obligations,
            decision_id="",
            effective_risk=effective_risk,
            required_assurance=required_assurance,
            session_assurance=session_assurance,
        )

    return PolicyDecision(
        allowed=True,
        reason="Access granted by risk policy",
        required_step_up=required_step_up,
        required_approval=required_approval,
        obligations=obligations,
        decision_id="",
        effective_risk=effective_risk,
        required_assurance=required_assurance,
        session_assurance=session_assurance,
    )
