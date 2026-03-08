"""Runtime Z3-backed admissibility evaluator for formal enforcement."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from z3 import And, Bool, BoolVal, Not, Solver, Z3Exception, sat, unsat

from .formal_models import AlphaContext, GammaKnowledgeBase


@dataclass(slots=True)
class Z3AdmissibilityResult:
    """Structured result for runtime Z3 admissibility checks."""

    admissible: bool
    status: str
    theorem_check: str
    negated_theorem_check: str
    witness: dict[str, Any]


@dataclass(slots=True)
class Z3RuntimeHealthStatus:
    """Health probe result for runtime Z3 availability."""

    available: bool
    healthy: bool
    check_result: str
    error: str | None = None


def _require_predicate_values(predicate_values: dict[str, bool]) -> None:
    required = {
        "AuthValid",
        "LineageValid",
        "PermitExists",
        "DenyExists",
        "ObligationsMet",
        "ContextBound",
    }
    missing = sorted(required - set(predicate_values))
    if missing:
        missing_text = ", ".join(missing)
        raise ValueError(f"Missing predicate values for Z3 evaluation: {missing_text}")


def check_admissibility_z3(
    alpha: AlphaContext,
    gamma: GammaKnowledgeBase,
    *,
    predicate_values: dict[str, bool],
) -> Z3AdmissibilityResult:
    """Evaluate admissibility theorem using runtime Z3 constraints.

    The function binds symbolic theorem predicates to concrete runtime predicate
    outcomes and performs solver checks for theorem and negated theorem.
    """
    _ = alpha, gamma
    _require_predicate_values(predicate_values)

    auth_valid = Bool("auth_valid")
    lineage_valid = Bool("lineage_valid")
    permit_exists = Bool("permit_exists")
    deny_exists = Bool("deny_exists")
    obligations_met = Bool("obligations_met")
    context_bound = Bool("context_bound")

    theorem = And(
        auth_valid,
        lineage_valid,
        permit_exists,
        Not(deny_exists),
        obligations_met,
        context_bound,
    )

    solver = Solver()
    solver.add(auth_valid == BoolVal(predicate_values["AuthValid"]))
    solver.add(lineage_valid == BoolVal(predicate_values["LineageValid"]))
    solver.add(permit_exists == BoolVal(predicate_values["PermitExists"]))
    solver.add(deny_exists == BoolVal(predicate_values["DenyExists"]))
    solver.add(obligations_met == BoolVal(predicate_values["ObligationsMet"]))
    solver.add(context_bound == BoolVal(predicate_values["ContextBound"]))

    base_check = solver.check()
    if base_check != sat:
        return Z3AdmissibilityResult(
            admissible=False,
            status="invalid_constraints",
            theorem_check=str(base_check),
            negated_theorem_check=str(base_check),
            witness={
                "base_check": str(base_check),
                "predicate_values": predicate_values,
            },
        )

    solver.push()
    solver.add(theorem)
    theorem_check = solver.check()
    solver.pop()

    solver.push()
    solver.add(Not(theorem))
    negated_theorem_check = solver.check()
    solver.pop()

    theorem_is_sat = theorem_check == sat
    theorem_is_unsat = theorem_check == unsat
    negated_is_sat = negated_theorem_check == sat
    negated_is_unsat = negated_theorem_check == unsat

    if theorem_is_sat and negated_is_unsat:
        admissible = True
        status = "consistent"
    elif theorem_is_unsat and negated_is_sat:
        admissible = False
        status = "consistent"
    else:
        admissible = False
        status = "inconclusive"

    return Z3AdmissibilityResult(
        admissible=admissible,
        status=status,
        theorem_check=str(theorem_check),
        negated_theorem_check=str(negated_theorem_check),
        witness={
            "predicate_values": predicate_values,
            "base_check": str(base_check),
        },
    )


def z3_runtime_healthcheck() -> Z3RuntimeHealthStatus:
    """Run a lightweight Z3 self-test used by startup and diagnostics endpoints."""
    try:
        solver = Solver()
        probe_flag = Bool("z3_runtime_probe")
        solver.add(probe_flag == BoolVal(True))
        check_result = solver.check()
        healthy = check_result == sat
        return Z3RuntimeHealthStatus(
            available=True,
            healthy=healthy,
            check_result=str(check_result),
            error=None if healthy else "Z3 solver health probe returned non-sat result",
        )
    except (RuntimeError, ValueError, Z3Exception) as exc:  # pragma: no cover - defensive
        return Z3RuntimeHealthStatus(
            available=False,
            healthy=False,
            check_result="error",
            error=str(exc),
        )


__all__ = [
    "Z3AdmissibilityResult",
    "Z3RuntimeHealthStatus",
    "check_admissibility_z3",
    "z3_runtime_healthcheck",
]
