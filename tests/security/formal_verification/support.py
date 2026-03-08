"""Shared fixtures and builders for formal verification chaos tests."""

from __future__ import annotations


def permit_policy() -> dict[str, object]:
    """Allow all action/resource operations."""
    return {
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


def deny_delete_prod_policy() -> dict[str, object]:
    """Deny destructive operations in production paths."""
    return {
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
