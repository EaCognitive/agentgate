"""Deterministic chaos verification runner built on the public verification API."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from random import Random
from typing import Any

from ea_agentgate.verification import check_admissibility, verify_certificate, verify_plan
from server.policy_governance.kernel.solver_engine import validate_runtime_z3_configuration


_PERMIT_POLICY = {
    "policy_json": {
        "pre_rules": [
            {
                "type": "permit",
                "action": "*",
                "resource": "*",
            }
        ]
    }
}
_DENY_DELETE_POLICY = {
    "policy_json": {
        "pre_rules": [
            {
                "type": "deny",
                "action": "delete",
                "resource": "/prod/*",
            }
        ]
    }
}


@dataclass(frozen=True, slots=True)
class _ChaosIterationResult:
    """Result for a single deterministic chaos iteration."""

    expected_decision: str
    actual_decision: str
    certificate_valid: bool
    violation_message: str | None


def _build_iteration_case(
    iteration: int,
    *,
    seed: int,
    compliance_profile: str,
    identity_profile: str,
) -> tuple[str, str, dict[str, Any]]:
    """Build a deterministic admissibility case for one iteration."""
    rng = Random(f"{seed}:{iteration}")
    action = "delete" if rng.randrange(7) == 0 else "read"
    resource = f"/prod/resource/{rng.randrange(100_000)}"
    runtime_context = {
        "iteration": iteration,
        "seed": seed,
        "compliance_profile": compliance_profile,
        "identity_profile": identity_profile,
    }
    return action, resource, runtime_context


def _run_iteration(
    iteration: int,
    *,
    seed: int,
    compliance_profile: str,
    identity_profile: str,
) -> _ChaosIterationResult:
    """Run one deterministic admissibility check."""
    action, resource, runtime_context = _build_iteration_case(
        iteration,
        seed=seed,
        compliance_profile=compliance_profile,
        identity_profile=identity_profile,
    )
    expected_decision = "INADMISSIBLE" if action == "delete" else "ADMISSIBLE"
    result = check_admissibility(
        principal=f"agent:chaos:{iteration % 11}",
        action=action,
        resource=resource,
        policies=[_PERMIT_POLICY, _DENY_DELETE_POLICY],
        tenant_id="chaos-verification",
        runtime_context=runtime_context,
    )
    certificate_result = verify_certificate(result.certificate_raw)
    violation_message: str | None = None
    if result.decision != expected_decision:
        violation_message = (
            f"iteration={iteration} expected={expected_decision} actual={result.decision}"
        )
    elif not certificate_result.valid:
        violation_message = f"iteration={iteration} produced an invalid certificate"
    return _ChaosIterationResult(
        expected_decision=expected_decision,
        actual_decision=result.decision,
        certificate_valid=certificate_result.valid,
        violation_message=violation_message,
    )


def _run_plan_invariant(seed: int) -> str | None:
    """Verify a deterministic multi-step plan still blocks destructive actions."""
    rng = Random(f"plan:{seed}")
    blocked_index = rng.randrange(3, 8)
    steps = [
        {"action": "read", "resource": f"/prod/object/{index}"}
        for index in range(blocked_index + 2)
    ]
    steps[blocked_index] = {"action": "delete", "resource": f"/prod/object/{blocked_index}"}
    result = verify_plan(
        principal="agent:chaos:plan",
        steps=steps,
        policies=[_PERMIT_POLICY, _DENY_DELETE_POLICY],
        tenant_id="chaos-verification",
    )
    if result.safe:
        return "plan invariant failed: destructive step was not blocked"
    if result.blocked_step_index != blocked_index:
        return (
            "plan invariant failed: unexpected blocked_step_index="
            f"{result.blocked_step_index}, expected={blocked_index}"
        )
    return None


def _evaluate_runtime_health(
    require_enforce_runtime: bool,
) -> tuple[int, list[str], dict[str, Any] | None]:
    """Validate runtime solver configuration for the chaos campaign."""
    try:
        runtime_status = validate_runtime_z3_configuration(
            require_solver_health=require_enforce_runtime,
        )
    except RuntimeError as exc:
        return 1, [str(exc)], None

    violations: list[str] = []
    if require_enforce_runtime and runtime_status["configured_mode"] != "enforce":
        violations.append(
            "runtime solver must be in enforce mode for this chaos campaign "
            f"(configured_mode={runtime_status['configured_mode']})"
        )
    return len(violations), violations, runtime_status


def run_chaos_verification(
    *,
    iterations: int,
    workers: int,
    seed: int,
    require_enforce_runtime: bool,
    compliance_profile: str,
    identity_profile: str,
    fail_fast_on_violation: bool,
) -> dict[str, Any]:
    """Run a deterministic chaos verification campaign and return a report."""
    runtime_violations, violation_messages, runtime_status = _evaluate_runtime_health(
        require_enforce_runtime
    )
    report: dict[str, Any] = {
        "iterations": iterations,
        "workers": workers,
        "seed": seed,
        "compliance_profile": compliance_profile,
        "identity_profile": identity_profile,
        "runtime_status": runtime_status,
        "admissible": 0,
        "inadmissible": 0,
        "certificate_failures": 0,
        "decision_mismatches": 0,
        "plan_violations": 0,
        "runtime_violations": runtime_violations,
        "invariant_violations": runtime_violations,
        "violations": violation_messages,
    }
    if fail_fast_on_violation and report["invariant_violations"]:
        return report

    plan_violation = _run_plan_invariant(seed)
    if plan_violation is not None:
        report["plan_violations"] += 1
        report["invariant_violations"] += 1
        report["violations"].append(plan_violation)
        if fail_fast_on_violation:
            return report

    if workers <= 1 or fail_fast_on_violation:
        iteration_results = (
            _run_iteration(
                iteration,
                seed=seed,
                compliance_profile=compliance_profile,
                identity_profile=identity_profile,
            )
            for iteration in range(iterations)
        )
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            iteration_results = pool.map(
                lambda iteration: _run_iteration(
                    iteration,
                    seed=seed,
                    compliance_profile=compliance_profile,
                    identity_profile=identity_profile,
                ),
                range(iterations),
            )

    for result in iteration_results:
        if result.actual_decision == "ADMISSIBLE":
            report["admissible"] += 1
        else:
            report["inadmissible"] += 1

        if not result.certificate_valid:
            report["certificate_failures"] += 1
            report["invariant_violations"] += 1

        if result.violation_message is not None:
            report["decision_mismatches"] += 1
            report["invariant_violations"] += 1
            report["violations"].append(result.violation_message)
            if fail_fast_on_violation:
                break

    return report


__all__ = ["run_chaos_verification"]
