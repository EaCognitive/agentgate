"""Bounded property-based synthesis engine for policy invariant discovery.

Generates randomized (AlphaContext, GammaKnowledgeBase) pairs, evaluates them
through the admissibility solver, and detects surprising or unstable results
that indicate potential policy gaps.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from server.models.formal_security_schemas import SynthesizedInvariantRecord
from server.utils.db import commit as db_commit
from server.utils.db import execute as db_execute
from .formal_models import (
    AlphaContext,
    DecisionResult,
    GammaKnowledgeBase,
    generate_uuid7,
)
from .solver_engine import evaluate_admissibility


PRINCIPAL_POOL = [
    "agent:operator",
    "agent:reviewer",
    "agent:auditor",
    "user:admin",
    "user:developer",
    "service:pipeline",
]

ACTION_POOL = [
    "read",
    "write",
    "delete",
    "execute",
    "approve",
    "block_ip_temp",
    "revoke_token",
    "apply_policy",
]

RESOURCE_POOL = [
    "/api/data",
    "/api/users",
    "/api/admin",
    "s3://bucket/object",
    "db://table/row",
    "/security/threats",
    "/security/settings",
]

OBLIGATION_TYPES = [
    "mfa_required",
    "approval_required",
    "preview_confirm_required",
]

POLICY_RULE_TYPES = ["permit", "deny", "action_allow", "action_deny"]

DEFAULT_ITERATIONS = 10_000
MAX_ITERATIONS = 100_000


class InvariantType(str, Enum):
    """Classification types for synthesized invariants."""

    INSTABILITY = "INSTABILITY"
    SURPRISING_ADMIT = "SURPRISING_ADMIT"
    SURPRISING_DENY = "SURPRISING_DENY"
    BOUNDARY = "BOUNDARY"


class ProposalStatus(str, Enum):
    """Status values for invariant proposals."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


@dataclass
class SynthesisConfig:
    """Configuration parameters for synthesis runs."""

    iterations: int = DEFAULT_ITERATIONS
    seed: int | None = None
    perturbation_ratio: float = 0.3
    instability_threshold: float = 0.05


@dataclass
class SynthesizedInvariant:
    """Discovered invariant from synthesis run."""

    invariant_id: str
    run_id: str
    invariant_type: InvariantType
    description: str
    dtsl_expression: str
    alpha_sample: dict[str, Any]
    gamma_sample: dict[str, Any]
    confidence_score: float
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class SynthesisRunResult:
    """Results from a completed synthesis run."""

    run_id: str
    iterations_completed: int
    invariants_found: list[SynthesizedInvariant]
    duration_ms: float
    trace: list[dict[str, Any]] = field(default_factory=list)


def _random_alpha(rng: random.Random) -> AlphaContext:
    """Generate a random AlphaContext from sampling pools.

    Args:
        rng: Seeded random number generator for reproducibility.

    Returns:
        A randomly-generated AlphaContext with deterministic hash.
    """
    principal = rng.choice(PRINCIPAL_POOL)
    action = rng.choice(ACTION_POOL)
    resource = rng.choice(RESOURCE_POOL)

    runtime_context = {
        "authenticated": rng.choice([True, False]),
        "direct_access": rng.choice([True, False]),
        "direct_permit": rng.choice([True, False]),
        "mfa_verified": rng.choice([True, False]),
        "preview_confirmed": rng.choice([True, False]),
        "execution_phase": rng.choice(["preview", "confirm"]),
    }

    return AlphaContext.from_runtime(
        principal=principal,
        action=action,
        resource=resource,
        runtime_context=runtime_context,
    )


def _random_gamma(
    rng: random.Random,
    alpha: AlphaContext,
) -> GammaKnowledgeBase:
    """Generate a random GammaKnowledgeBase aligned with alpha.

    Args:
        rng: Seeded random number generator for reproducibility.
        alpha: The alpha context to align with (uses same principal).

    Returns:
        A randomly-generated GammaKnowledgeBase with computed hash.
    """
    num_policies = rng.randint(0, 3)
    policies = []
    for _ in range(num_policies):
        num_rules = rng.randint(1, 3)
        policy_json = {"pre_rules": [], "post_rules": []}
        for _ in range(num_rules):
            rule_type = rng.choice(POLICY_RULE_TYPES)
            rule = {
                "type": rule_type,
                "action": rng.choice(ACTION_POOL + ["*"]),
                "resource": rng.choice(RESOURCE_POOL + ["*"]),
            }
            if rng.choice([True, False]):
                policy_json["pre_rules"].append(rule)
            else:
                policy_json["post_rules"].append(rule)
        policies.append({"policy_json": policy_json})

    num_obligations = rng.randint(0, 2)
    obligations = []
    for _ in range(num_obligations):
        obligations.append(
            {
                "type": rng.choice(OBLIGATION_TYPES),
                "operation": rng.choice(ACTION_POOL),
            }
        )

    blocked_ops = []
    if rng.choice([True, False]):
        blocked_ops.append(rng.choice(ACTION_POOL))

    gamma = GammaKnowledgeBase(
        principal=alpha.principal,
        tenant_id="tenant-synth",
        facts=[],
        active_grants=[],
        active_revocations=[],
        policies=policies,
        obligations=obligations,
        environment={"blocked_operations": blocked_ops},
    )
    gamma.compute_gamma_hash()
    return gamma


def _perturb_gamma(
    rng: random.Random,
    gamma: GammaKnowledgeBase,
) -> GammaKnowledgeBase:
    """Create a perturbed copy of gamma with exactly one mutation.

    Args:
        rng: Seeded random number generator for reproducibility.
        gamma: The original knowledge base to perturb.

    Returns:
        A new GammaKnowledgeBase with a single mutation applied.
    """
    mutation_type = rng.choice(
        [
            "toggle_rule",
            "toggle_obligation",
            "toggle_blocked_op",
        ]
    )

    new_policies = [dict(p) for p in gamma.policies]
    new_obligations = [dict(o) for o in gamma.obligations]
    new_env = dict(gamma.environment)
    blocked_ops = list(new_env.get("blocked_operations", []))

    if mutation_type == "toggle_rule" and new_policies:
        policy_idx = rng.randint(0, len(new_policies) - 1)
        policy_json = dict(new_policies[policy_idx].get("policy_json", {}))
        pre_rules = list(policy_json.get("pre_rules", []))
        post_rules = list(policy_json.get("post_rules", []))

        if pre_rules and rng.choice([True, False]):
            pre_rules.pop()
        elif post_rules:
            post_rules.pop()
        else:
            new_rule = {
                "type": rng.choice(POLICY_RULE_TYPES),
                "action": rng.choice(ACTION_POOL),
                "resource": rng.choice(RESOURCE_POOL),
            }
            pre_rules.append(new_rule)

        policy_json["pre_rules"] = pre_rules
        policy_json["post_rules"] = post_rules
        new_policies[policy_idx]["policy_json"] = policy_json

    elif mutation_type == "toggle_obligation":
        if new_obligations and rng.choice([True, False]):
            new_obligations.pop()
        else:
            new_obligations.append(
                {
                    "type": rng.choice(OBLIGATION_TYPES),
                    "operation": rng.choice(ACTION_POOL),
                }
            )

    elif mutation_type == "toggle_blocked_op":
        if blocked_ops and rng.choice([True, False]):
            blocked_ops.pop()
        else:
            blocked_ops.append(rng.choice(ACTION_POOL))
        new_env["blocked_operations"] = blocked_ops

    perturbed = GammaKnowledgeBase(
        principal=gamma.principal,
        tenant_id=gamma.tenant_id,
        facts=list(gamma.facts),
        active_grants=list(gamma.active_grants),
        active_revocations=list(gamma.active_revocations),
        policies=new_policies,
        obligations=new_obligations,
        environment=new_env,
    )
    perturbed.compute_gamma_hash()
    return perturbed


def _classify_surprise(
    alpha: AlphaContext,
    gamma: GammaKnowledgeBase,
    cert: Any,
    _perturbed_gamma: GammaKnowledgeBase,
    perturbed_cert: Any,
) -> SynthesizedInvariant | None:
    """Classify whether the decision pair reveals a policy invariant.

    Args:
        alpha: The action context evaluated.
        gamma: Original knowledge base.
        cert: Original decision certificate.
        perturbed_gamma: Perturbed knowledge base.
        perturbed_cert: Decision certificate for perturbed gamma.

    Returns:
        SynthesizedInvariant if a surprise is detected, None otherwise.
    """
    run_id = str(generate_uuid7())
    invariant_id = str(generate_uuid7())

    if cert.result != perturbed_cert.result:
        return SynthesizedInvariant(
            invariant_id=invariant_id,
            run_id=run_id,
            invariant_type=InvariantType.INSTABILITY,
            description=(
                f"Decision flipped from {cert.result} to "
                f"{perturbed_cert.result} under minimal perturbation for "
                f"action={alpha.action}"
            ),
            dtsl_expression=_generate_dtsl_expression(
                InvariantType.INSTABILITY,
                alpha,
                gamma,
                cert,
            ),
            alpha_sample=alpha.model_dump(mode="json"),
            gamma_sample=gamma.model_dump(mode="json"),
            confidence_score=0.8,
        )

    if cert.result == DecisionResult.ADMISSIBLE:
        deny_rules_exist = any(
            any(
                rule.get("type") in {"deny", "action_deny"}
                for rule in p.get("policy_json", {}).get("pre_rules", [])
            )
            for p in gamma.policies
        )
        blocked_ops = gamma.environment.get("blocked_operations", [])
        if deny_rules_exist or blocked_ops:
            return SynthesizedInvariant(
                invariant_id=invariant_id,
                run_id=run_id,
                invariant_type=InvariantType.SURPRISING_ADMIT,
                description=(
                    f"Admitted despite deny pattern present for "
                    f"action={alpha.action} resource={alpha.resource}"
                ),
                dtsl_expression=_generate_dtsl_expression(
                    InvariantType.SURPRISING_ADMIT,
                    alpha,
                    gamma,
                    cert,
                ),
                alpha_sample=alpha.model_dump(mode="json"),
                gamma_sample=gamma.model_dump(mode="json"),
                confidence_score=0.7,
            )

    if cert.result == DecisionResult.INADMISSIBLE:
        has_deny_rules = any(
            any(
                rule.get("type") in {"deny", "action_deny"}
                for rule in p.get("policy_json", {}).get("pre_rules", [])
            )
            for p in gamma.policies
        )
        has_permits = any(
            any(
                rule.get("type") in {"permit", "action_allow"}
                for rule in p.get("policy_json", {}).get("pre_rules", [])
            )
            for p in gamma.policies
        )
        blocked_ops = gamma.environment.get("blocked_operations", [])
        if not has_deny_rules and has_permits and not blocked_ops:
            return SynthesizedInvariant(
                invariant_id=invariant_id,
                run_id=run_id,
                invariant_type=InvariantType.SURPRISING_DENY,
                description=(
                    f"Denied despite no explicit deny rules for "
                    f"action={alpha.action} resource={alpha.resource}"
                ),
                dtsl_expression=_generate_dtsl_expression(
                    InvariantType.SURPRISING_DENY,
                    alpha,
                    gamma,
                    cert,
                ),
                alpha_sample=alpha.model_dump(mode="json"),
                gamma_sample=gamma.model_dump(mode="json"),
                confidence_score=0.75,
            )

    return None


def _generate_dtsl_expression(
    invariant_type: InvariantType,
    alpha: AlphaContext,
    _gamma: GammaKnowledgeBase,
    _cert: Any,
) -> str:
    """Generate human-readable DTSL candidate rule text.

    Args:
        invariant_type: The type of invariant detected.
        alpha: The action context.
        gamma: The knowledge base.
        cert: The decision certificate.

    Returns:
        A DTSL-like rule expression describing the invariant.
    """
    if invariant_type == InvariantType.INSTABILITY:
        return (
            f"WHEN action={alpha.action} AND resource={alpha.resource} "
            f"THEN REVIEW_POLICY /* instability detected */"
        )

    if invariant_type == InvariantType.SURPRISING_ADMIT:
        return (
            f"WHEN action={alpha.action} AND resource={alpha.resource} "
            f"THEN DENY /* unexpected admit despite deny pattern */"
        )

    if invariant_type == InvariantType.SURPRISING_DENY:
        return (
            f"WHEN action={alpha.action} AND resource={alpha.resource} "
            f"THEN PERMIT /* unexpected deny without deny rules */"
        )

    return f"WHEN action={alpha.action} THEN REVIEW"


async def run_synthesis(config: SynthesisConfig) -> SynthesisRunResult:
    """Execute bounded synthesis fuzzing run.

    Args:
        config: Synthesis configuration parameters.

    Returns:
        SynthesisRunResult containing discovered invariants and metrics.
    """
    iterations = min(config.iterations, MAX_ITERATIONS)
    rng = random.Random(config.seed)
    run_id = str(generate_uuid7())
    invariants: list[SynthesizedInvariant] = []
    trace: list[dict[str, Any]] = []

    start_time = time.time()

    for iteration in range(iterations):
        alpha = _random_alpha(rng)
        gamma = _random_gamma(rng, alpha)
        cert = evaluate_admissibility(alpha, gamma)

        perturbed_gamma = _perturb_gamma(rng, gamma)
        perturbed_cert = evaluate_admissibility(alpha, perturbed_gamma)

        invariant = _classify_surprise(
            alpha,
            gamma,
            cert,
            perturbed_gamma,
            perturbed_cert,
        )

        if invariant:
            invariants.append(invariant)
            trace.append(
                {
                    "iteration": iteration,
                    "invariant_type": invariant.invariant_type.value,
                    "alpha_hash": alpha.alpha_hash,
                    "gamma_hash": gamma.gamma_hash,
                }
            )

    end_time = time.time()
    duration_ms = (end_time - start_time) * 1000

    return SynthesisRunResult(
        run_id=run_id,
        iterations_completed=iterations,
        invariants_found=invariants,
        duration_ms=duration_ms,
        trace=trace,
    )


async def get_pending_proposals(
    session: AsyncSession,
    *,
    status_filter: str = "pending",
) -> list[dict[str, Any]]:
    """Retrieve pending invariant proposals from database.

    Args:
        session: Async database session.
        status_filter: Status value to filter by (default: "pending").

    Returns:
        List of proposal records as dictionaries.
    """
    statement = select(SynthesizedInvariantRecord).where(
        SynthesizedInvariantRecord.status == status_filter
    )
    result = await db_execute(session, statement)
    records = result.scalars().all()
    return [record.model_dump() for record in records]


async def approve_proposal(
    session: AsyncSession,
    invariant_id: str,
) -> bool:
    """Approve a pending invariant proposal.

    Args:
        session: Async database session.
        invariant_id: Unique identifier for the proposal.

    Returns:
        True if approval succeeded, False if proposal not found.
    """
    statement = select(SynthesizedInvariantRecord).where(
        SynthesizedInvariantRecord.invariant_id == invariant_id
    )
    result = await db_execute(session, statement)
    proposal = result.scalar_one_or_none()

    if not proposal:
        return False

    proposal.status = ProposalStatus.APPROVED.value
    proposal.reviewed_at = datetime.now(timezone.utc).replace(tzinfo=None)
    session.add(proposal)
    await db_commit(session)
    return True


async def reject_proposal(
    session: AsyncSession,
    invariant_id: str,
    *,
    reason: str = "",
) -> bool:
    """Reject a pending invariant proposal.

    Args:
        session: Async database session.
        invariant_id: Unique identifier for the proposal.
        reason: Optional rejection reason (for audit purposes).

    Returns:
        True if rejection succeeded, False if proposal not found.
    """
    statement = select(SynthesizedInvariantRecord).where(
        SynthesizedInvariantRecord.invariant_id == invariant_id
    )
    result = await db_execute(session, statement)
    proposal = result.scalar_one_or_none()

    if not proposal:
        return False

    proposal.status = ProposalStatus.REJECTED.value
    proposal.reviewed_at = datetime.now(timezone.utc).replace(tzinfo=None)
    if reason:
        proposal.reviewed_by = f"rejected: {reason}"
    session.add(proposal)
    await db_commit(session)
    return True


async def persist_synthesis_results(
    session: AsyncSession,
    result: SynthesisRunResult,
) -> int:
    """Persist synthesis run invariants to database.

    Args:
        session: Async database session.
        result: Synthesis run result containing invariants.

    Returns:
        Count of invariants persisted.
    """
    count = 0
    for invariant in result.invariants_found:
        record = SynthesizedInvariantRecord(
            invariant_id=invariant.invariant_id,
            run_id=invariant.run_id,
            invariant_type=invariant.invariant_type.value,
            description=invariant.description,
            dtsl_expression=invariant.dtsl_expression,
            alpha_sample=invariant.alpha_sample,
            gamma_sample=invariant.gamma_sample,
            confidence_score=invariant.confidence_score,
            status=ProposalStatus.PENDING.value,
            created_at=invariant.created_at.replace(tzinfo=None),
        )
        session.add(record)
        count += 1

    await db_commit(session)
    return count
