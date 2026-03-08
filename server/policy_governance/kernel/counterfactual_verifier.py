"""Bounded counterfactual verifier for multi-step execution plans."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from .formal_models import AlphaContext, DecisionResult
from .gamma_builder import GammaBuilder
from .solver_engine import evaluate_admissibility


RISK_BOUNDS = {
    "low": 5,
    "medium": 10,
    "high": 20,
    "critical": 30,
}


@dataclass(slots=True)
class CounterfactualVerificationResult:
    """Result for bounded counterfactual verification."""

    safe: bool
    risk_tier: str
    evaluated_steps: int
    bound: int
    blocked_step_index: int | None
    counterexample: dict[str, Any] | None
    trace: list[dict[str, Any]]


async def verify_counterfactual_plan(
    session: AsyncSession,
    *,
    principal: str,
    tenant_id: str | None,
    steps: list[dict[str, Any]],
    risk_tier: str,
) -> CounterfactualVerificationResult:
    """Verify bounded plan safety before execution using admissibility theorem."""
    normalized_tier = risk_tier.lower()
    if normalized_tier not in RISK_BOUNDS:
        raise ValueError(f"Unsupported risk tier: {risk_tier}")

    bound = RISK_BOUNDS[normalized_tier]
    bounded_steps = steps[:bound]

    trace: list[dict[str, Any]] = []
    gamma_builder = GammaBuilder(session)

    for index, step in enumerate(bounded_steps):
        action = str(step.get("action", "")).strip().lower()
        resource = str(step.get("resource", "")).strip()
        context = dict(step.get("context", {}))
        context.setdefault("authenticated", True)
        context.setdefault("direct_access", True)
        context.setdefault("direct_permit", True)
        context.setdefault("execution_phase", "confirm")
        context.setdefault("preview_confirmed", True)

        alpha = AlphaContext.from_runtime(
            principal=principal,
            action=action,
            resource=resource,
            runtime_context=context,
            tenant_id=tenant_id,
            delegation_ref=step.get("delegation_ref"),
        )
        gamma_result = await gamma_builder.build(alpha)
        certificate = evaluate_admissibility(alpha, gamma_result.gamma)

        trace.append(
            {
                "step_index": index,
                "action": action,
                "resource": resource,
                "decision_id": str(certificate.decision_id),
                "result": certificate.result.value,
                "proof_type": certificate.proof_type.value,
            }
        )

        if certificate.result == DecisionResult.INADMISSIBLE:
            return CounterfactualVerificationResult(
                safe=False,
                risk_tier=normalized_tier,
                evaluated_steps=index + 1,
                bound=bound,
                blocked_step_index=index,
                counterexample={
                    "step": step,
                    "decision_certificate": certificate.model_dump(mode="json"),
                },
                trace=trace,
            )

    return CounterfactualVerificationResult(
        safe=True,
        risk_tier=normalized_tier,
        evaluated_steps=len(bounded_steps),
        bound=bound,
        blocked_step_index=None,
        counterexample=None,
        trace=trace,
    )
