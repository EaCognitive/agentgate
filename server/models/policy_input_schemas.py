"""Pydantic input schemas for policy creation.

These models provide:
1. Automatic JSON Schema generation for MCP tool inputSchema
2. Self-documenting field descriptions
3. Validation before passing to policy engine
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class PolicyConditionInput(BaseModel):
    """A condition to evaluate against request context."""

    field: str = Field(description="Field to check (e.g., 'agent_id', 'geo_country', 'source_ip')")
    operator: Literal[
        "eq",
        "neq",
        "in",
        "not_in",
        "contains",
        "not_contains",
        "matches",
        "gt",
        "lt",
        "gte",
        "lte",
        "exists",
        "not_exists",
    ] = Field(description="Comparison operator")
    value: Any = Field(description="Value to compare against (string, number, list, or regex)")


class PolicyRuleInput(BaseModel):
    """A single policy rule with conditions and effect."""

    rule_id: str = Field(description="Unique identifier for this rule")
    effect: Literal["allow", "deny"] = Field(description="Action when rule matches")
    description: str = Field(default="", description="Human-readable description of the rule")
    priority: int = Field(default=0, description="Higher priority wins conflicts (default: 0)")
    conditions: list[PolicyConditionInput] = Field(
        default_factory=list, description="Conditions that must all be true for rule to match"
    )


class PolicySetInput(BaseModel):
    """Input schema for creating a security policy set.

    Example:
        {
            "policy_set_id": "finance-agent-policy",
            "version": "1.0.0",
            "default_effect": "allow",
            "description": "Block non-US traffic for Finance-Agent",
            "rules": [
                {
                    "rule_id": "block-non-us",
                    "effect": "deny",
                    "priority": 100,
                    "conditions": [
                        {"field": "geo_country", "operator": "neq", "value": "US"}
                    ]
                }
            ]
        }
    """

    policy_set_id: str = Field(description="Unique identifier for the policy set")
    version: str = Field(description="Semantic version string (e.g., '1.0.0')")
    default_effect: Literal["allow", "deny"] = Field(description="Effect when no rules match")
    description: str = Field(default="", description="Human-readable description of the policy")
    rules: list[PolicyRuleInput] = Field(
        default_factory=list, description="List of rules to evaluate"
    )


# Export JSON Schema for documentation
POLICY_SET_SCHEMA = PolicySetInput.model_json_schema()
