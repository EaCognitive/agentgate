"""Deterministic admissibility solver for proof-carrying enforcement.

Implements the theorem:
    Admissible(alpha, Gamma) := AuthValid and LineageValid and PermitExists and
    not DenyExists and ObligationsMet and ContextBound
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

from server.metrics import (
    record_z3_drift,
    record_z3_eval,
    record_z3_eval_failure,
)
from .delegation_lineage import LineageValidationResult, validate_lineage_chain
from .formal_models import (
    AlphaContext,
    DecisionCertificate,
    DecisionResult,
    GammaKnowledgeBase,
    ProofType,
    canonical_json,
    load_private_key,
    sha256_hex,
    theorem_hash_for_expression,
)
from .z3_runtime_engine import (
    Z3AdmissibilityResult,
    Z3RuntimeHealthStatus,
    check_admissibility_z3,
    z3_runtime_healthcheck,
)


logger = logging.getLogger(__name__)

RUNTIME_Z3_MODE_ENV = "AGENTGATE_Z3_MODE"
VALID_RUNTIME_Z3_MODES = {"off", "shadow", "enforce"}
_LOCAL_RUNTIME_ENVIRONMENTS = {"local", "development", "dev", "test"}
_TRUE_VALUES = {"1", "true", "yes", "on"}


THEOREM_EXPRESSION = (
    "auth_valid(alpha,gamma) and "
    "lineage_valid(alpha,gamma) and "
    "permit_exists(alpha,gamma) and "
    "not deny_exists(alpha,gamma) and "
    "obligations_met(alpha,gamma) and "
    "context_bound(alpha,gamma)"
)


@dataclass(slots=True)
class PredicateOutcome:
    """Outcome for theorem predicate evaluation."""

    name: str
    value: bool
    witness: dict[str, Any]


@dataclass(slots=True)
class PredicateBundle:
    """Grouped predicate outcomes for admissibility evaluation."""

    auth: PredicateOutcome
    lineage: PredicateOutcome
    permit: PredicateOutcome
    deny: PredicateOutcome
    obligations: PredicateOutcome
    context: PredicateOutcome


@dataclass(slots=True)
class RuntimeEvaluationRequest:
    """Runtime solver evaluation inputs."""

    runtime_mode: str
    runtime_config_error: str | None
    python_admissible: bool
    predicates: PredicateBundle
    alpha: AlphaContext
    gamma: GammaKnowledgeBase


def _runtime_z3_mode() -> str:
    config = validate_runtime_z3_configuration(
        require_solver_health=False,
    )
    configured_mode = config.get("configured_mode")
    if isinstance(configured_mode, str):
        return configured_mode
    raise RuntimeError("Invalid runtime Z3 configuration: configured_mode must be a string.")


def _runtime_environment() -> str:
    env = os.getenv("AGENTGATE_ENV", os.getenv("ENV", "development"))
    return env.strip().lower() or "development"


def _testing_enabled() -> bool:
    return os.getenv("TESTING", "").strip().lower() in _TRUE_VALUES


def _is_local_runtime_environment() -> bool:
    return _runtime_environment() in _LOCAL_RUNTIME_ENVIRONMENTS or _testing_enabled()


def validate_runtime_z3_configuration(
    *,
    require_solver_health: bool,
) -> dict[str, Any]:
    """Validate runtime Z3 configuration and enforce production safety contracts."""
    configured_mode = os.getenv(RUNTIME_Z3_MODE_ENV, "off").strip().lower()
    environment = _runtime_environment()
    local_env = _is_local_runtime_environment()

    if configured_mode not in VALID_RUNTIME_Z3_MODES:
        if local_env:
            logger.warning(
                "Invalid %s value '%s' in %s runtime; defaulting to off",
                RUNTIME_Z3_MODE_ENV,
                configured_mode,
                environment,
            )
            configured_mode = "off"
        else:
            raise RuntimeError(
                f"Invalid {RUNTIME_Z3_MODE_ENV} value '{configured_mode}' "
                f"for environment '{environment}'."
            )

    if configured_mode == "off" and not local_env:
        raise RuntimeError(
            f"{RUNTIME_Z3_MODE_ENV}=off is restricted to local/dev/test runtimes. "
            f"Current environment='{environment}'."
        )

    health_status = Z3RuntimeHealthStatus(
        available=True,
        healthy=True,
        check_result="not_checked",
        error=None,
    )
    if require_solver_health:
        health_status = z3_runtime_healthcheck()
    if require_solver_health and configured_mode in {"shadow", "enforce"}:
        if not health_status.available or not health_status.healthy:
            error_text = health_status.error or "unknown runtime Z3 health probe failure"
            raise RuntimeError(
                f"Runtime Z3 healthcheck failed in mode '{configured_mode}': {error_text}"
            )

    return {
        "configured_mode": configured_mode,
        "environment": environment,
        "off_mode_allowed": local_env,
        "z3_available": health_status.available,
        "z3_healthy": health_status.healthy,
        "z3_check_result": health_status.check_result,
        "z3_error": health_status.error,
    }


def _resource_scope_matches(scope: str, resource: str) -> bool:
    if scope == "*":
        return True
    if scope.endswith("*"):
        return resource.startswith(scope[:-1])
    return scope == resource


def _actions_contain(required_action: str, allowed_actions: list[str]) -> bool:
    return "*" in allowed_actions or required_action in allowed_actions


def _match_policy_rule(alpha: AlphaContext, rule: dict[str, Any]) -> bool:
    """Evaluate policy rule match against alpha context."""
    rule_type = rule.get("type", "")
    matched = False
    if rule_type in {"action_allow", "action_deny"}:
        candidate = str(rule.get("action", "")).strip().lower()
        matched = candidate in {"*", alpha.action}
    elif rule_type in {"permit", "deny"}:
        candidate_action = str(rule.get("action", "*")).strip().lower()
        candidate_resource = str(rule.get("resource", "*")).strip()
        matched = (
            candidate_action in {"*", alpha.action}
            and _resource_scope_matches(candidate_resource, alpha.resource)
        )
    elif rule_type in {"ip_deny", "ip_allow"}:
        source_ip = str(alpha.runtime_context.get("source_ip", "")).strip()
        cidr = str(rule.get("cidr", "")).strip()
        if not source_ip or not cidr:
            return False
        # Prefix check fallback keeps evaluation deterministic without external deps.
        matched = source_ip == cidr or source_ip.startswith(cidr.split("/", maxsplit=1)[0])
    elif rule_type == "endpoint_allow":
        endpoint = str(alpha.runtime_context.get("endpoint", "")).strip()
        expected = str(rule.get("endpoint", "")).strip()
        matched = bool(endpoint and expected and endpoint.startswith(expected))
    elif rule_type in {"role_allow", "role_deny"}:
        user_role = str(alpha.runtime_context.get("role", "")).strip().lower()
        candidate_role = str(rule.get("role", "")).strip().lower()
        matched = bool(user_role and candidate_role and candidate_role in {user_role, "*"})
    return matched


def _extract_policy_rules(
    gamma: GammaKnowledgeBase,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Extract allow/deny rule candidates from active policy set."""
    allow_rules: list[dict[str, Any]] = []
    deny_rules: list[dict[str, Any]] = []

    for policy in gamma.policies:
        policy_json = policy.get("policy_json", {})

        for rule in policy_json.get("pre_rules", []):
            rule_type = rule.get("type")
            if rule_type in {"ip_deny", "action_deny", "deny", "role_deny"}:
                deny_rules.append(rule)
            elif rule_type in {
                "ip_allow",
                "action_allow",
                "permit",
                "endpoint_allow",
                "role_allow",
            }:
                allow_rules.append(rule)

        for rule in policy_json.get("post_rules", []):
            rule_type = rule.get("type")
            if rule_type in {"deny", "action_deny", "role_deny"}:
                deny_rules.append(rule)
            elif rule_type in {"permit", "action_allow", "role_allow"}:
                allow_rules.append(rule)

    return allow_rules, deny_rules


def _auth_valid(alpha: AlphaContext, gamma: GammaKnowledgeBase) -> PredicateOutcome:
    authenticated = bool(alpha.runtime_context.get("authenticated", True))
    same_principal = gamma.principal == alpha.principal
    value = authenticated and same_principal
    witness = {
        "authenticated": authenticated,
        "gamma_principal": gamma.principal,
        "alpha_principal": alpha.principal,
    }
    return PredicateOutcome(name="AuthValid", value=value, witness=witness)


def _lineage_valid(alpha: AlphaContext, gamma: GammaKnowledgeBase) -> PredicateOutcome:
    if not gamma.active_grants and not alpha.delegation_ref:
        direct_access = bool(alpha.runtime_context.get("direct_access", True))
        return PredicateOutcome(
            name="LineageValid",
            value=direct_access,
            witness={"mode": "direct", "direct_access": direct_access},
        )

    lineage_result: LineageValidationResult = validate_lineage_chain(
        principal=alpha.principal,
        action=alpha.action,
        resource=alpha.resource,
        tenant_id=alpha.tenant_id,
        grants=gamma.active_grants,
        revocations=gamma.active_revocations,
        required_delegation_ref=alpha.delegation_ref,
    )
    return PredicateOutcome(
        name="LineageValid",
        value=lineage_result.valid,
        witness={
            "reason": lineage_result.reason,
            "chain": lineage_result.chain,
            "details": lineage_result.witness,
        },
    )


def _permit_exists(alpha: AlphaContext, gamma: GammaKnowledgeBase) -> PredicateOutcome:
    allow_rules, _ = _extract_policy_rules(gamma)

    matched_policy_rules = [rule for rule in allow_rules if _match_policy_rule(alpha, rule)]
    matched_grants = [
        grant["grant_id"]
        for grant in gamma.active_grants
        if _actions_contain(alpha.action, grant.get("allowed_actions", []))
        and _resource_scope_matches(grant.get("resource_scope", "*"), alpha.resource)
    ]

    direct_permit = bool(alpha.runtime_context.get("direct_permit", False))

    # When no policies are configured and no grants exist,
    # the system is unconfigured -- fail open with clear witness.
    unconfigured = not gamma.policies and not gamma.active_grants
    value = bool(matched_policy_rules or matched_grants or direct_permit or unconfigured)

    return PredicateOutcome(
        name="PermitExists",
        value=value,
        witness={
            "policy_matches": matched_policy_rules,
            "grant_matches": matched_grants,
            "direct_permit": direct_permit,
            "unconfigured_fallback": unconfigured,
        },
    )


def _deny_exists(alpha: AlphaContext, gamma: GammaKnowledgeBase) -> PredicateOutcome:
    _, deny_rules = _extract_policy_rules(gamma)
    evaluated_rules: list[dict[str, Any]] = []
    matched_rule: dict[str, Any] | None = None

    blocked_operations = set(gamma.environment.get("blocked_operations", []))
    if alpha.action in blocked_operations:
        matched_rule = {
            "type": "guardrail_block",
            "operation": alpha.action,
            "source": "guardrails",
        }

    for rule in deny_rules:
        matched = _match_policy_rule(alpha, rule)
        evaluated_rules.append({"rule": rule, "matched": matched})
        if matched and matched_rule is None:
            matched_rule = rule

    value = matched_rule is not None
    witness = {
        "matched_rule": matched_rule,
        "evaluated_rules": evaluated_rules,
        "deny_absence_proof": {
            "mode": "EXHAUSTIVE_RULE_EVALUATION",
            "checked_rule_count": len(evaluated_rules),
            "matched_count": 1 if matched_rule else 0,
        },
    }
    return PredicateOutcome(name="DenyExists", value=value, witness=witness)


def _obligations_met(alpha: AlphaContext, gamma: GammaKnowledgeBase) -> PredicateOutcome:
    context = alpha.runtime_context
    failures: list[dict[str, Any]] = []

    for obligation in gamma.obligations:
        obligation_type = obligation.get("type")
        operation = obligation.get("operation")

        if operation and operation != alpha.action:
            continue

        if (
            obligation_type == "mfa_required"
            and bool(context.get("enforce_mfa_obligation", False))
            and not bool(context.get("mfa_verified", False))
        ):
            failures.append({"obligation": obligation, "reason": "mfa_not_verified"})
        elif (
            obligation_type == "approval_required"
            and not bool(context.get("human_approved", False))
            and context.get("execution_phase") == "confirm"
        ):
            failures.append({"obligation": obligation, "reason": "approval_missing"})
        elif (
            obligation_type == "preview_confirm_required"
            and context.get("execution_phase") == "confirm"
            and not bool(context.get("preview_confirmed", False))
        ):
            failures.append({"obligation": obligation, "reason": "preview_confirm_missing"})

    return PredicateOutcome(
        name="ObligationsMet",
        value=not failures,
        witness={"failures": failures, "checked_count": len(gamma.obligations)},
    )


def _context_bound(alpha: AlphaContext, gamma: GammaKnowledgeBase) -> PredicateOutcome:
    expected_hash = sha256_hex(canonical_json(alpha.runtime_context))
    value = alpha.context_hash == expected_hash
    return PredicateOutcome(
        name="ContextBound",
        value=value,
        witness={
            "expected_hash": expected_hash,
            "provided_hash": alpha.context_hash,
            "gamma_hash": gamma.gamma_hash,
        },
    )


def _run_z3_evaluation(
    runtime_mode: str,
    predicate_values: dict[str, bool],
    alpha: AlphaContext,
    gamma: GammaKnowledgeBase,
    python_admissible: bool,
) -> tuple[Z3AdmissibilityResult | None, str | None, bool, bool]:
    """Execute Z3 runtime evaluation and reconcile with Python result.

    Runs the Z3 solver, detects drift between the Python and Z3 outcomes,
    and applies mode-specific admissibility semantics (enforce vs shadow).

    Args:
        runtime_mode: Active Z3 mode (``"shadow"`` or ``"enforce"``).
        predicate_values: Predicate truth values from the Python solver.
        alpha: Alpha context for the evaluation.
        gamma: Gamma knowledge base for the evaluation.
        python_admissible: Whether the Python solver deemed admissible.

    Returns:
        Tuple of (z3_result, failure_reason, drift_detected, admissible).
    """
    z3_result: Z3AdmissibilityResult | None = None
    runtime_failure_reason: str | None = None
    drift_detected = False
    admissible = python_admissible

    try:
        z3_result = check_admissibility_z3(
            alpha,
            gamma,
            predicate_values=predicate_values,
        )
        if z3_result.status != "consistent":
            raise RuntimeError(
                f"Runtime Z3 solver returned an inconclusive result: {z3_result.status}"
            )

        if z3_result.admissible != python_admissible:
            drift_detected = True
            record_z3_drift(runtime_mode)
            logger.error(
                "Runtime solver drift detected mode=%s python=%s z3=%s",
                runtime_mode,
                python_admissible,
                z3_result.admissible,
            )

        if runtime_mode == "enforce":
            admissible = z3_result.admissible
        else:
            admissible = python_admissible

        if drift_detected:
            admissible = False

        record_z3_eval(runtime_mode, admissible)
    except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
        record_z3_eval_failure(runtime_mode)
        runtime_failure_reason = str(exc)
        logger.exception(
            "Runtime Z3 evaluation failed mode=%s",
            runtime_mode,
        )
        # Enforce and shadow modes both fail closed on solver issues.
        admissible = False
        record_z3_eval(runtime_mode, admissible)

    return z3_result, runtime_failure_reason, drift_detected, admissible


def _apply_runtime_overrides(
    request: RuntimeEvaluationRequest,
) -> tuple[Z3AdmissibilityResult | None, str | None, bool, bool]:
    """Dispatch Z3 runtime evaluation based on mode and config state.

    Returns:
        Tuple of (z3_result, failure_reason, drift_detected, admissible).
    """
    if request.runtime_config_error is not None:
        record_z3_eval_failure("config_error")
        record_z3_eval("config_error", False)
        return None, request.runtime_config_error, False, False

    if request.runtime_mode == "off":
        record_z3_eval(request.runtime_mode, request.python_admissible)
        return None, None, False, request.python_admissible

    predicate_values = {
        "AuthValid": request.predicates.auth.value,
        "LineageValid": request.predicates.lineage.value,
        "PermitExists": request.predicates.permit.value,
        "DenyExists": request.predicates.deny.value,
        "ObligationsMet": request.predicates.obligations.value,
        "ContextBound": request.predicates.context.value,
    }
    return _run_z3_evaluation(
        request.runtime_mode,
        predicate_values,
        request.alpha,
        request.gamma,
        request.python_admissible,
    )


def _runtime_solver_backend(runtime_mode: str) -> str:
    """Map runtime mode to the backend label used in certificates."""
    if runtime_mode == "off":
        return "python"
    if runtime_mode == "enforce":
        return "z3"
    return "python+z3"


def _runtime_solver_payload(
    *,
    runtime_mode: str,
    alpha: AlphaContext,
    python_admissible: bool,
    z3_result: Z3AdmissibilityResult | None,
    runtime_failure_reason: str | None,
    drift_detected: bool,
) -> dict[str, Any]:
    """Build the runtime solver payload for decision proofs."""
    payload: dict[str, Any] = {
        "solver_mode": runtime_mode,
        "solver_backend": _runtime_solver_backend(runtime_mode),
        "principal": alpha.principal,
        "action": alpha.action,
        "resource": alpha.resource,
        "python_result": python_admissible,
        "z3_result": (z3_result.admissible if z3_result is not None else None),
        "z3_check_result": (
            z3_result.status
            if z3_result is not None
            else ("error" if runtime_failure_reason else "not_run")
        ),
        "drift_detected": drift_detected,
        "failure_reason": runtime_failure_reason,
    }
    if z3_result is not None:
        payload["theorem_check"] = z3_result.theorem_check
        payload["negated_theorem_check"] = z3_result.negated_theorem_check
        payload["z3_witness"] = z3_result.witness
    return payload


def _proof_payload_for_admissible(
    outcomes: list[PredicateOutcome],
    deny_outcome: PredicateOutcome,
    runtime_solver_payload: dict[str, Any],
) -> dict[str, Any]:
    """Build the constructive proof payload."""
    return {
        "constructive_trace": [
            {
                "predicate": outcome.name,
                "value": outcome.value,
                "witness": outcome.witness,
            }
            for outcome in outcomes
        ],
        "deny_absence_proof": deny_outcome.witness.get("deny_absence_proof", {}),
        "runtime_solver": runtime_solver_payload,
    }


def _build_outcomes(
    alpha: AlphaContext,
    gamma: GammaKnowledgeBase,
) -> tuple[list[PredicateOutcome], PredicateBundle]:
    """Evaluate all theorem predicates and return the ordered outcomes."""
    auth_outcome = _auth_valid(alpha, gamma)
    lineage_outcome = _lineage_valid(alpha, gamma)
    permit_outcome = _permit_exists(alpha, gamma)
    deny_outcome = _deny_exists(alpha, gamma)
    obligations_outcome = _obligations_met(alpha, gamma)
    context_outcome = _context_bound(alpha, gamma)
    outcomes = [
        auth_outcome,
        lineage_outcome,
        permit_outcome,
        PredicateOutcome(
            "NotDenyExists",
            not deny_outcome.value,
            deny_outcome.witness,
        ),
        obligations_outcome,
        context_outcome,
    ]
    return outcomes, PredicateBundle(
        auth=auth_outcome,
        lineage=lineage_outcome,
        permit=permit_outcome,
        deny=deny_outcome,
        obligations=obligations_outcome,
        context=context_outcome,
    )


def _resolve_runtime_mode() -> tuple[str, str | None]:
    """Resolve runtime solver mode and config error state."""
    runtime_mode = "off"
    runtime_config_error: str | None = None
    try:
        runtime_mode = _runtime_z3_mode()
    except RuntimeError as exc:
        runtime_mode = "enforce"
        runtime_config_error = str(exc)
        logger.error(
            "Runtime solver configuration error: %s",
            runtime_config_error,
        )
    return runtime_mode, runtime_config_error


def _resolve_false_predicates(
    outcomes: list[PredicateOutcome],
    admissible: bool,
    runtime_failure_reason: str | None,
    drift_detected: bool,
) -> list[str]:
    """Return the false predicate list, including runtime solver failures."""
    false_predicates = [outcome.name for outcome in outcomes if not outcome.value]
    if admissible or false_predicates:
        return false_predicates
    if runtime_failure_reason:
        return ["Z3EvaluationError"]
    if drift_detected:
        return ["Z3DecisionMismatch"]
    return false_predicates


def _build_certificate_payload(
    *,
    admissible: bool,
    deny_outcome: PredicateOutcome,
    outcomes: list[PredicateOutcome],
    false_predicates: list[str],
    runtime_solver_payload: dict[str, Any],
) -> tuple[DecisionResult, ProofType, dict[str, Any]]:
    """Build the decision result, proof type, and payload."""
    if admissible:
        return (
            DecisionResult.ADMISSIBLE,
            ProofType.CONSTRUCTIVE_TRACE,
            _proof_payload_for_admissible(outcomes, deny_outcome, runtime_solver_payload),
        )
    if deny_outcome.value:
        return (
            DecisionResult.INADMISSIBLE,
            ProofType.COUNTEREXAMPLE,
            _proof_payload_for_denial(
                deny_outcome,
                false_predicates,
                runtime_solver_payload,
            ),
        )
    return (
        DecisionResult.INADMISSIBLE,
        ProofType.UNSAT_CORE,
        _proof_payload_for_unsat(outcomes, false_predicates, runtime_solver_payload),
    )


def _proof_payload_for_denial(
    deny_outcome: PredicateOutcome,
    false_predicates: list[str],
    runtime_solver_payload: dict[str, Any],
) -> dict[str, Any]:
    """Build the counterexample payload."""
    return {
        "counterexample": {
            "predicate": "DenyExists",
            "witness": deny_outcome.witness.get("matched_rule"),
        },
        "evaluated_rules": deny_outcome.witness.get("evaluated_rules", []),
        "failed_predicates": false_predicates,
        "runtime_solver": runtime_solver_payload,
    }


def _proof_payload_for_unsat(
    outcomes: list[PredicateOutcome],
    false_predicates: list[str],
    runtime_solver_payload: dict[str, Any],
) -> dict[str, Any]:
    """Build the unsat-core proof payload."""
    return {
        "unsat_core": false_predicates,
        "trace": [
            {
                "predicate": outcome.name,
                "value": outcome.value,
                "witness": outcome.witness,
            }
            for outcome in outcomes
        ],
        "runtime_solver": runtime_solver_payload,
    }


def evaluate_admissibility(
    alpha: AlphaContext,
    gamma: GammaKnowledgeBase,
) -> DecisionCertificate:
    """Evaluate theorem and return signed decision certificate."""
    if not gamma.gamma_hash:
        gamma.compute_gamma_hash()

    outcomes, predicate_bundle = _build_outcomes(alpha, gamma)

    python_admissible = all(outcome.value for outcome in outcomes)
    runtime_mode, runtime_config_error = _resolve_runtime_mode()
    runtime_request = RuntimeEvaluationRequest(
        runtime_mode=runtime_mode,
        runtime_config_error=runtime_config_error,
        python_admissible=python_admissible,
        predicates=predicate_bundle,
        alpha=alpha,
        gamma=gamma,
    )
    z3_result, runtime_failure_reason, drift_detected, admissible = _apply_runtime_overrides(
        runtime_request,
    )

    false_predicates = _resolve_false_predicates(
        outcomes,
        admissible,
        runtime_failure_reason,
        drift_detected,
    )

    runtime_solver_payload = _runtime_solver_payload(
        runtime_mode=runtime_mode,
        alpha=alpha,
        python_admissible=python_admissible,
        z3_result=z3_result,
        runtime_failure_reason=runtime_failure_reason,
        drift_detected=drift_detected,
    )
    result, proof_type, proof_payload = _build_certificate_payload(
        admissible=admissible,
        deny_outcome=predicate_bundle.deny,
        outcomes=outcomes,
        false_predicates=false_predicates,
        runtime_solver_payload=runtime_solver_payload,
    )

    certificate = DecisionCertificate(
        theorem_hash=theorem_hash_for_expression(THEOREM_EXPRESSION),
        result=result,
        proof_type=proof_type,
        proof_payload=proof_payload,
        alpha_hash=alpha.alpha_hash,
        gamma_hash=gamma.gamma_hash or gamma.compute_gamma_hash(),
    )
    certificate.sign(load_private_key())
    return certificate
