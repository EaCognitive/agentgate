"""Policy-as-Code engine for declarative security rules.

Provides OPA/Rego-inspired policy evaluation with JSON-based rule definitions.
Supports hot-swapping policies without code deploys.
"""

from __future__ import annotations

import re
import threading
import time
from pathlib import Path
from typing import Any

from ea_agentgate.security.policy_parser import (
    parse_policy_set,
    validate_policy_set,
)
from ea_agentgate.security.policy_io import load_policy_json
from ea_agentgate.security.policy_types import (
    ConditionOperator,
    PolicyCondition,
    PolicyDecision,
    PolicyEffect,
    PolicyRule,
    PolicySet,
)


# =============================================================================
# Policy Engine
# =============================================================================


class PolicyEngine:
    """Evaluates requests against policy sets.

    Thread-safe policy management with hot-swapping support.
    Policies are evaluated in priority order, with highest priority
    rule winning in case of conflicts.

    Example:
        engine = PolicyEngine()
        policy_set = engine.load_policy_from_file("policies/default.json")
        engine.load_policy_set(policy_set)

        decision = engine.evaluate(
            policy_set_id="default",
            request_context={
                "request": {
                    "tool": "delete_file",
                    "inputs": {"path": "/etc/passwd"},
                    "user": {"role": "user"},
                }
            }
        )

        if not decision.allowed:
            raise PermissionError(decision.reason)
    """

    def __init__(self) -> None:
        """Initialize policy engine with empty policy registry."""
        self._policy_sets: dict[str, PolicySet] = {}
        self._lock = threading.RLock()

    def load_policy_set(self, policy_set: PolicySet) -> None:
        """Register a policy set for evaluation.

        Args:
            policy_set: The policy set to load.

        Raises:
            ValueError: If the policy set is invalid.
        """
        errors = validate_policy_set(policy_set)
        if errors:
            raise ValueError(
                f"Invalid policy set '{policy_set.policy_set_id}': {'; '.join(errors)}"
            )

        with self._lock:
            self._policy_sets[policy_set.policy_set_id] = policy_set

    def load_policy_from_dict(self, data: dict[str, Any]) -> PolicySet:
        """Parse a policy set from a dictionary.

        Args:
            data: Dictionary conforming to policy set schema.

        Returns:
            A fully constructed PolicySet instance.

        Raises:
            ValueError: If required fields are missing or invalid.
        """
        return parse_policy_set(data)

    def load_policy_from_file(self, path: str | Path) -> PolicySet:
        """Load a policy set from a JSON file.

        Args:
            path: Path to the JSON policy file.

        Returns:
            A fully constructed PolicySet instance.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the JSON is invalid or does not conform
                to the policy schema.
        """
        file_path, data = load_policy_json(path)

        try:
            return self.load_policy_from_dict(data)
        except ValueError as exc:
            raise ValueError(f"Invalid policy in '{file_path}': {exc}") from exc

    def unload_policy_set(self, policy_set_id: str) -> None:
        """Remove a policy set from the engine.

        Enables hot-swapping of policies.

        Args:
            policy_set_id: ID of the policy set to remove.

        Raises:
            KeyError: If the policy set does not exist.
        """
        with self._lock:
            if policy_set_id not in self._policy_sets:
                raise KeyError(f"Policy set '{policy_set_id}' not found")
            del self._policy_sets[policy_set_id]

    def evaluate(
        self,
        policy_set_id: str,
        request_context: dict[str, Any],
    ) -> PolicyDecision:
        """Evaluate a request against a specific policy set.

        Args:
            policy_set_id: ID of the policy set to evaluate.
            request_context: Request context dictionary with nested
                fields accessible via dot notation.

        Returns:
            A PolicyDecision with the evaluation result.

        Raises:
            KeyError: If the policy set does not exist.
        """
        start_time = time.time()

        with self._lock:
            if policy_set_id not in self._policy_sets:
                raise KeyError(f"Policy set '{policy_set_id}' not found")
            policy_set = self._policy_sets[policy_set_id]

        matched_rules: list[str] = []
        winning_effect: PolicyEffect | None = None
        winning_priority = -1

        for rule in policy_set.rules:
            if _evaluate_rule(rule, request_context):
                matched_rules.append(rule.rule_id)

                if rule.priority > winning_priority:
                    winning_priority = rule.priority
                    winning_effect = rule.effect

        if winning_effect is None:
            final_effect = policy_set.default_effect
            reason = f"No rules matched, using default effect: {final_effect.value}"
        else:
            final_effect = winning_effect
            reason = f"Matched rules: {', '.join(matched_rules)}, effect: {final_effect.value}"

        elapsed_ms = (time.time() - start_time) * 1000

        return PolicyDecision(
            allowed=(final_effect == PolicyEffect.ALLOW),
            effect=final_effect,
            matched_rules=matched_rules,
            reason=reason,
            policy_set_id=policy_set_id,
            evaluation_time_ms=elapsed_ms,
        )

    def evaluate_all(
        self,
        request_context: dict[str, Any],
    ) -> PolicyDecision:
        """Evaluate against all loaded policy sets.

        Uses highest priority winning rule across all sets.
        If no rules match in any set, uses DENY as default.

        Args:
            request_context: Request context dictionary.

        Returns:
            A PolicyDecision with the combined evaluation result.
        """
        start_time = time.time()

        with self._lock:
            policy_sets = list(self._policy_sets.values())

        if not policy_sets:
            return PolicyDecision(
                allowed=False,
                effect=PolicyEffect.DENY,
                matched_rules=[],
                reason="No policy sets loaded",
                policy_set_id="<none>",
                evaluation_time_ms=0.0,
            )

        all_matched_rules: list[str] = []
        winning_effect: PolicyEffect | None = None
        winning_priority = -1
        winning_policy_id = ""

        for policy_set in policy_sets:
            for rule in policy_set.rules:
                if _evaluate_rule(rule, request_context):
                    rule_ref = f"{policy_set.policy_set_id}:{rule.rule_id}"
                    all_matched_rules.append(rule_ref)

                    if rule.priority > winning_priority:
                        winning_priority = rule.priority
                        winning_effect = rule.effect
                        winning_policy_id = policy_set.policy_set_id

        if winning_effect is None:
            final_effect = PolicyEffect.DENY
            reason = "No rules matched across all policy sets, denying by default"
            winning_policy_id = "<default>"
        else:
            final_effect = winning_effect
            reason = f"Matched rules: {', '.join(all_matched_rules)}, effect: {final_effect.value}"

        elapsed_ms = (time.time() - start_time) * 1000

        return PolicyDecision(
            allowed=(final_effect == PolicyEffect.ALLOW),
            effect=final_effect,
            matched_rules=all_matched_rules,
            reason=reason,
            policy_set_id=winning_policy_id,
            evaluation_time_ms=elapsed_ms,
        )

    def list_loaded_policies(self) -> list[str]:
        """Return list of loaded policy set IDs.

        Returns:
            List of policy set IDs currently loaded.
        """
        with self._lock:
            return list(self._policy_sets.keys())


# =============================================================================
# Evaluation Helpers
# =============================================================================


def _evaluate_rule(
    rule: PolicyRule,
    context: dict[str, Any],
) -> bool:
    """Evaluate if a rule matches the request context.

    All conditions must be true for the rule to match.

    Args:
        rule: The rule to evaluate.
        context: Request context dictionary.

    Returns:
        True if all conditions match, False otherwise.
    """
    for condition in rule.conditions:
        if not _evaluate_condition(condition, context):
            return False
    return True


def _evaluate_comparison(
    field_value: Any,
    expected: Any,
    operator: ConditionOperator,
) -> bool:
    """Evaluate comparison operators (GT, LT, GE, LE).

    Args:
        field_value: The field value to compare.
        expected: The expected value.
        operator: The comparison operator.

    Returns:
        True if comparison passes, False otherwise.
    """
    try:
        field_float = float(field_value)
        expected_float = float(expected)

        if operator == ConditionOperator.GREATER_THAN:
            return field_float > expected_float
        if operator == ConditionOperator.LESS_THAN:
            return field_float < expected_float
        if operator == ConditionOperator.GREATER_EQUAL:
            return field_float >= expected_float
        if operator == ConditionOperator.LESS_EQUAL:
            return field_float <= expected_float
    except (ValueError, TypeError):
        pass

    return False


def _evaluate_contains(
    field_value: Any,
    expected: Any,
    negate: bool = False,
) -> bool:
    """Evaluate contains/not_contains operators.

    Args:
        field_value: The field value to check.
        expected: The value to find.
        negate: If True, check for NOT_CONTAINS instead.

    Returns:
        True if condition passes, False otherwise.
    """
    result = False

    if isinstance(field_value, str):
        result = str(expected) in field_value
    elif isinstance(field_value, list):
        result = expected in field_value
    else:
        result = False

    return not result if negate else result


def _evaluate_equality_or_membership(
    field_value: Any,
    expected: Any,
    operator: ConditionOperator,
) -> bool:
    """Evaluate equality or membership operators.

    Args:
        field_value: The field value.
        expected: The expected value.
        operator: The operator (EQUALS, NOT_EQUALS, IN, NOT_IN).

    Returns:
        True if condition passes, False otherwise.
    """
    # Handle equality checks
    if operator in (ConditionOperator.EQUALS, ConditionOperator.NOT_EQUALS):
        is_equal = field_value == expected
        return is_equal if operator == ConditionOperator.EQUALS else not is_equal

    # Handle membership checks
    if not isinstance(expected, list):
        return operator == ConditionOperator.NOT_IN
    is_in = field_value in expected
    return is_in if operator == ConditionOperator.IN else not is_in


def _evaluate_regex_or_comparison(
    field_value: Any,
    expected: Any,
    operator: ConditionOperator,
) -> bool:
    """Evaluate regex matching or comparison operators.

    Args:
        field_value: The field value.
        expected: The expected value.
        operator: The operator (MATCHES, GT, LT, GE, LE, or other).

    Returns:
        True if condition passes, False otherwise.
    """
    if operator == ConditionOperator.MATCHES:
        return (
            isinstance(field_value, str)
            and isinstance(expected, str)
            and bool(re.search(expected, field_value))
        )

    # Handle comparison operators
    return _evaluate_comparison(field_value, expected, operator)


def _evaluate_condition(
    condition: PolicyCondition,
    context: dict[str, Any],
) -> bool:
    """Evaluate a single condition against the context.

    Args:
        condition: The condition to evaluate.
        context: Request context dictionary.

    Returns:
        True if the condition matches, False otherwise.
    """
    field_value = _get_field_value(condition.field, context)
    operator = condition.operator
    expected = condition.value

    # Handle existence checks
    if operator in (ConditionOperator.EXISTS, ConditionOperator.NOT_EXISTS):
        is_exists = field_value is not None
        return is_exists if operator == ConditionOperator.EXISTS else not is_exists

    # All other operators require non-null field_value
    if field_value is None:
        return False

    # Handle equality and membership checks
    if operator in (
        ConditionOperator.EQUALS,
        ConditionOperator.NOT_EQUALS,
        ConditionOperator.IN,
        ConditionOperator.NOT_IN,
    ):
        return _evaluate_equality_or_membership(field_value, expected, operator)

    # Handle contains/not_contains
    if operator in (ConditionOperator.CONTAINS, ConditionOperator.NOT_CONTAINS):
        return _evaluate_contains(
            field_value, expected, negate=(operator == ConditionOperator.NOT_CONTAINS)
        )

    # Handle regex matching and comparison operators
    return _evaluate_regex_or_comparison(field_value, expected, operator)


def _get_field_value(
    field_path: str,
    context: dict[str, Any],
) -> Any:
    """Extract a field value using dot notation.

    Args:
        field_path: Dot-separated path (e.g., "request.tool.name").
        context: Context dictionary to traverse.

    Returns:
        The field value, or None if the path does not exist.
    """
    parts = field_path.split(".")
    current: Any = context

    for part in parts:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
        if current is None:
            return None

    return current


# Re-export all public API from this module
__all__ = [
    "ConditionOperator",
    "PolicyEffect",
    "PolicyCondition",
    "PolicyRule",
    "PolicySet",
    "PolicyDecision",
    "PolicyEngine",
    "validate_policy_set",
]
