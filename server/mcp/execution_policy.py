"""Central MCP execution policy classification and guardrail enforcement."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any

from server.metrics import record_mcp_guardrail_denial

from .api_client import MCPApiClientError, get_api_client
from .guardrails import GuardrailCheckResult, check_operation
from .monitoring import emit_failure_alert

logger = logging.getLogger(__name__)


class OperationClass(str, Enum):
    """Classification for MCP operation risk and side-effect expectations."""

    READ = "read"
    MUTATING = "mutating"
    HIGH_IMPACT_MUTATING = "high_impact_mutating"


_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# High-impact operations already routed through preview-confirm + MFA workflows.
_HIGH_IMPACT_OPERATIONS = frozenset(
    {
        "block_ip_temp",
        "unblock_ip",
        "revoke_token",
        "create_incident",
        "apply_policy",
        "unlock_policy",
    }
)

# POST operations that are computational/read-only by design.
_READ_OPERATION_OVERRIDES = frozenset(
    {
        "mcp_policies_evaluate",
        "mcp_pii_detect",
        "mcp_pii_restore",
        "mcp_security_verify_certificate",
        "mcp_counterfactual_verify",
        "mcp_evidence_verify_chain",
        "mcp_guardrails_status",
        "mcp_mfa_status",
        "mcp_mfa_providers",
        "mcp_totp_setup",
        "score_threat",
        "generate_redteam_payloads",
        "mcp_check_job_status",
        "mcp_list_jobs",
    }
)


class ExecutionPolicyError(RuntimeError):
    """Raised when execution policy denies an MCP operation."""

    def __init__(self, payload: dict[str, Any]):
        self.payload = payload
        super().__init__(json.dumps(payload, indent=2, default=str))


@dataclass(frozen=True)
class ExecutionPolicyDecision:
    """Result of classifying and checking an MCP operation."""

    operation_class: OperationClass
    guardrail_result: GuardrailCheckResult | None


def classify_operation(operation: str, method: str | None = None) -> OperationClass:
    """Classify an MCP operation based on operation name and transport method."""
    normalized_operation = operation.strip()
    if normalized_operation in _HIGH_IMPACT_OPERATIONS:
        return OperationClass.HIGH_IMPACT_MUTATING

    if normalized_operation in _READ_OPERATION_OVERRIDES:
        return OperationClass.READ

    normalized_method = (method or "").strip().upper()
    if normalized_method in _MUTATING_METHODS:
        return OperationClass.MUTATING

    return OperationClass.READ


def _policy_payload(
    *,
    operation: str,
    operation_class: OperationClass,
    error_code: str,
    message: str,
    context: dict[str, Any],
    decision_certificate: dict[str, Any] | None,
    reason: str | None = None,
) -> dict[str, Any]:
    payload = {
        "success": False,
        "operation": operation,
        "operation_class": operation_class.value,
        "error": error_code,
        "message": message,
        "status_code": 403,
        "context": context,
        "guardrails_enforced": True,
    }
    if reason:
        payload["reason"] = reason
    if decision_certificate:
        payload["decision_certificate"] = decision_certificate
    return payload


def _policy_event_details(
    *,
    operation: str,
    operation_class: OperationClass,
    context: dict[str, Any],
    outcome: str,
    reason: str,
) -> dict[str, Any]:
    return {
        "operation": operation,
        "operation_class": operation_class.value,
        "outcome": outcome,
        "reason": reason,
        "context": context,
    }


async def _emit_policy_audit_event(
    *,
    event_type: str,
    operation: str,
    operation_class: OperationClass,
    context: dict[str, Any],
    outcome: str,
    reason: str,
) -> None:
    """Best-effort audit emission for execution policy decisions."""
    details = _policy_event_details(
        operation=operation,
        operation_class=operation_class,
        context=context,
        outcome=outcome,
        reason=reason,
    )

    try:
        await get_api_client().post(
            "/api/audit",
            body={
                "event_type": event_type,
                "tool": operation,
                "result": outcome,
                "details": details,
            },
        )
    except MCPApiClientError as exc:
        logger.warning(
            "Failed to emit MCP execution-policy audit event: %s (operation=%s, status=%s)",
            event_type,
            operation,
            exc.status_code,
        )


async def enforce_execution_policy(
    operation: str,
    *,
    method: str | None = None,
    context: dict[str, Any] | None = None,
) -> ExecutionPolicyDecision:
    """Enforce guardrails for mutating operations before execution."""
    runtime_context = dict(context or {})
    operation_class = classify_operation(operation, method=method)

    if operation_class == OperationClass.READ:
        return ExecutionPolicyDecision(
            operation_class=operation_class,
            guardrail_result=None,
        )

    try:
        guardrail_result = await check_operation(operation, runtime_context)
    except Exception as exc:  # pragma: no cover - defensive fail-closed path
        record_mcp_guardrail_denial("error")
        await _emit_policy_audit_event(
            event_type="MCP_EXECUTION_POLICY_ERROR",
            operation=operation,
            operation_class=operation_class,
            context=runtime_context,
            outcome="error",
            reason=str(exc),
        )
        await emit_failure_alert(
            event_type="mcp_execution_policy_error",
            title="MCP execution policy evaluation error",
            description="Execution policy check failed and operation was blocked fail-closed.",
            severity="critical",
            correlation_id=None,
            details={
                "operation": operation,
                "operation_class": operation_class.value,
                "reason": str(exc),
            },
        )
        payload = _policy_payload(
            operation=operation,
            operation_class=operation_class,
            error_code="execution_policy_error",
            message="Execution policy evaluation failed and was blocked fail-closed.",
            reason=str(exc),
            context=runtime_context,
            decision_certificate=None,
        )
        raise ExecutionPolicyError(payload) from exc

    if guardrail_result.allowed:
        return ExecutionPolicyDecision(
            operation_class=operation_class,
            guardrail_result=guardrail_result,
        )

    if guardrail_result.requires_approval:
        record_mcp_guardrail_denial("approval_required")
        await _emit_policy_audit_event(
            event_type="MCP_EXECUTION_POLICY_DENIED_APPROVAL",
            operation=operation,
            operation_class=operation_class,
            context=runtime_context,
            outcome="denied",
            reason=guardrail_result.reason,
        )
        await emit_failure_alert(
            event_type="mcp_execution_policy_requires_approval",
            title="MCP operation requires approval",
            description=guardrail_result.reason,
            severity="medium",
            correlation_id=None,
            details={
                "operation": operation,
                "operation_class": operation_class.value,
            },
        )
        payload = _policy_payload(
            operation=operation,
            operation_class=operation_class,
            error_code="human_approval_required",
            message=guardrail_result.reason,
            reason=guardrail_result.reason,
            context=runtime_context,
            decision_certificate=guardrail_result.decision_certificate,
        )
        raise ExecutionPolicyError(payload)

    record_mcp_guardrail_denial("blocked")
    await _emit_policy_audit_event(
        event_type="MCP_EXECUTION_POLICY_DENIED",
        operation=operation,
        operation_class=operation_class,
        context=runtime_context,
        outcome="blocked",
        reason=guardrail_result.reason,
    )
    await emit_failure_alert(
        event_type="mcp_execution_policy_denied",
        title="MCP operation blocked by guardrails",
        description=guardrail_result.reason,
        severity="high",
        correlation_id=None,
        details={
            "operation": operation,
            "operation_class": operation_class.value,
        },
    )
    payload = _policy_payload(
        operation=operation,
        operation_class=operation_class,
        error_code="blocked_by_guardrails",
        message=guardrail_result.reason,
        reason=guardrail_result.reason,
        context=runtime_context,
        decision_certificate=guardrail_result.decision_certificate,
    )
    raise ExecutionPolicyError(payload)
