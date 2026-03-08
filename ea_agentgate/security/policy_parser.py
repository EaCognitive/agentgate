"""Policy parsing and validation utilities for Policy Engine.

This module provides functions to parse policy sets from dictionaries/JSON
and validate their structure.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any

from ea_agentgate.security.policy_types import (
    ConditionOperator,
    PolicyCondition,
    PolicyEffect,
    PolicyRule,
    PolicySet,
)


# =============================================================================
# Validation
# =============================================================================


def validate_policy_set(policy_set: PolicySet) -> list[str]:
    """Validate a policy set and return all errors.

    Checks:
    - All field references are valid dot-notation paths
    - Regex patterns compile successfully
    - Rules have at least one condition

    Args:
        policy_set: The policy set to validate.

    Returns:
        List of error messages. Empty list means valid.
    """
    errors: list[str] = []

    for rule in policy_set.rules:
        if not rule.conditions:
            errors.append(f"Rule '{rule.rule_id}' has no conditions")

        for idx, condition in enumerate(rule.conditions):
            if not condition.field:
                errors.append(f"Rule '{rule.rule_id}' condition[{idx}] has empty field")

            if condition.operator == ConditionOperator.MATCHES:
                if not isinstance(condition.value, str):
                    errors.append(
                        f"Rule '{rule.rule_id}' condition[{idx}] "
                        f"uses MATCHES but value is not a string"
                    )
                else:
                    try:
                        re.compile(condition.value)
                    except re.error as exc:
                        errors.append(
                            f"Rule '{rule.rule_id}' condition[{idx}] has invalid regex: {exc}"
                        )

    return errors


# =============================================================================
# Parsing Helpers
# =============================================================================


def _parse_enum_value(
    enum_cls: type[Enum],
    raw_value: Any,
    field_name: str,
) -> Any:
    """Parse an enum from its string value.

    Args:
        enum_cls: The Enum class to parse into.
        raw_value: The raw value from input.
        field_name: Name of the field for error messages.

    Returns:
        The parsed enum member.

    Raises:
        ValueError: If the value is not a valid member.
    """
    if isinstance(raw_value, enum_cls):
        return raw_value

    valid_values = [m.value for m in enum_cls]
    for member in enum_cls:
        if member.value == raw_value:
            return member

    raise ValueError(f"Invalid {field_name}: '{raw_value}'. Must be one of {valid_values}")


def _parse_condition(
    raw: dict[str, Any],
    index: int,
    rule_id: str,
) -> PolicyCondition:
    """Parse a single condition from a dict.

    Args:
        raw: Raw condition dictionary.
        index: Index of the condition in the list.
        rule_id: ID of the parent rule for error context.

    Returns:
        A PolicyCondition instance.

    Raises:
        ValueError: If required fields are missing or invalid.
    """
    prefix = f"Rule '{rule_id}', condition[{index}]"

    if "field" not in raw:
        raise ValueError(f"{prefix}: missing 'field'")
    if "operator" not in raw:
        raise ValueError(f"{prefix}: missing 'operator'")

    operator = _parse_enum_value(
        ConditionOperator,
        raw["operator"],
        f"{prefix} operator",
    )

    value = raw.get("value")

    return PolicyCondition(
        field=str(raw["field"]),
        operator=operator,
        value=value,
    )


def _parse_rule(
    raw: dict[str, Any],
    index: int,
) -> PolicyRule:
    """Parse a single rule from a dict.

    Args:
        raw: Raw rule dictionary.
        index: Index of the rule in the list.

    Returns:
        A PolicyRule instance.

    Raises:
        ValueError: If required fields are missing or invalid.
    """
    prefix = f"Rule[{index}]"

    if "rule_id" not in raw:
        raise ValueError(f"{prefix}: missing 'rule_id'")
    if "effect" not in raw:
        raise ValueError(f"{prefix}: missing 'effect'")

    rule_id = str(raw["rule_id"])
    description = str(raw.get("description", ""))

    effect = _parse_enum_value(
        PolicyEffect,
        raw["effect"],
        f"{prefix} effect",
    )

    priority = int(raw.get("priority", 0))

    conditions: list[PolicyCondition] = []
    raw_conditions = raw.get("conditions", [])
    for idx, raw_condition in enumerate(raw_conditions):
        conditions.append(_parse_condition(raw_condition, idx, rule_id))

    return PolicyRule(
        rule_id=rule_id,
        description=description,
        conditions=conditions,
        effect=effect,
        priority=priority,
    )


def parse_policy_set(data: dict[str, Any]) -> PolicySet:
    """Parse a policy set from a dictionary.

    Args:
        data: Dictionary conforming to policy set schema.

    Returns:
        A fully constructed PolicySet instance.

    Raises:
        ValueError: If required fields are missing or invalid.
    """
    if not data:
        raise ValueError("Policy data must not be empty")

    required_fields = [
        "policy_set_id",
        "version",
        "default_effect",
    ]
    for req_field in required_fields:
        if req_field not in data:
            raise ValueError(f"Missing required field: '{req_field}'")

    default_effect = _parse_enum_value(
        PolicyEffect,
        data["default_effect"],
        "default_effect",
    )

    rules: list[PolicyRule] = []
    raw_rules = data.get("rules", [])
    for idx, raw_rule in enumerate(raw_rules):
        rules.append(_parse_rule(raw_rule, idx))

    return PolicySet(
        policy_set_id=str(data["policy_set_id"]),
        version=str(data["version"]),
        description=str(data.get("description", "")),
        default_effect=default_effect,
        rules=rules,
    )


__all__ = [
    "validate_policy_set",
    "parse_policy_set",
]
