"""Data types for the Policy Engine.

Contains enumerations and dataclasses used throughout the policy system.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# =============================================================================
# Enumerations
# =============================================================================


class ConditionOperator(str, Enum):
    """Operators for policy condition evaluation."""

    EQUALS = "eq"
    NOT_EQUALS = "neq"
    IN = "in"
    NOT_IN = "not_in"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    MATCHES = "matches"
    GREATER_THAN = "gt"
    LESS_THAN = "lt"
    GREATER_EQUAL = "gte"
    LESS_EQUAL = "lte"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"


class PolicyEffect(str, Enum):
    """Policy decision outcomes."""

    ALLOW = "allow"
    DENY = "deny"


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class PolicyCondition:
    """A single condition to evaluate against request context.

    Args:
        field: Dot-notation path to field (e.g., "request.tool.name").
        operator: Comparison operator to apply.
        value: Expected value for comparison. Can be string, number,
            list, or regex pattern.
    """

    field: str
    operator: ConditionOperator
    value: Any


@dataclass
class PolicyRule:
    """A single evaluable rule with conditions and effect.

    Args:
        rule_id: Unique identifier for this rule.
        description: Human-readable description of the rule.
        conditions: List of conditions (all must be true for rule to match).
        effect: ALLOW or DENY when rule matches.
        priority: Higher priority wins conflicts (default: 0).
    """

    rule_id: str
    description: str
    conditions: list[PolicyCondition]
    effect: PolicyEffect
    priority: int = 0


@dataclass
class PolicySet:
    """Collection of rules with a default effect.

    Args:
        policy_set_id: Unique identifier for this policy set.
        version: Semantic version string.
        description: Human-readable description.
        default_effect: Applied when no rules match.
        rules: List of rules to evaluate.
    """

    policy_set_id: str
    version: str
    description: str
    default_effect: PolicyEffect
    rules: list[PolicyRule] = field(default_factory=list)


@dataclass
class PolicyDecision:
    """Result of policy evaluation.

    Args:
        allowed: Whether the request is allowed.
        effect: The effect that was applied.
        matched_rules: List of rule IDs that matched.
        reason: Human-readable explanation of the decision.
        policy_set_id: ID of the policy set that made the decision.
        evaluation_time_ms: Time taken to evaluate (milliseconds).
    """

    allowed: bool
    effect: PolicyEffect
    matched_rules: list[str]
    reason: str
    policy_set_id: str
    evaluation_time_ms: float


__all__ = [
    "ConditionOperator",
    "PolicyEffect",
    "PolicyCondition",
    "PolicyRule",
    "PolicySet",
    "PolicyDecision",
]
