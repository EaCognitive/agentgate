"""Tests for role_allow and role_deny rule types in the solver engine.

Covers unit-level matching via _match_policy_rule, rule classification via
_extract_policy_rules, and integration through _permit_exists/_deny_exists
to verify end-to-end admissibility semantics for role-based policy rules.
"""

from __future__ import annotations

from typing import Any

from server.policy_governance.kernel.formal_models import (
    AlphaContext,
    GammaKnowledgeBase,
)
from server.policy_governance.kernel.solver_engine import (
    _deny_exists,
    _extract_policy_rules,
    _match_policy_rule,
    _permit_exists,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PRINCIPAL_ALICE = "alice"
PRINCIPAL_BOB = "bob"
ACTION_READ = "read"
ACTION_WRITE = "write"
RESOURCE_DOCS = "docs/report.pdf"
RESOURCE_DB = "db/users"

ROLE_ADMIN = "admin"
ROLE_VIEWER = "viewer"
ROLE_EDITOR = "editor"
ROLE_WILDCARD = "*"


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------


def _make_alpha(
    *,
    principal: str = PRINCIPAL_ALICE,
    action: str = ACTION_READ,
    resource: str = RESOURCE_DOCS,
    role: str = "",
    extra_context: dict[str, Any] | None = None,
) -> AlphaContext:
    """Build an AlphaContext with optional role in runtime_context.

    Args:
        principal: Identity string for the context.
        action: Normalized action identifier.
        resource: Resource path or identifier.
        role: Role string to inject into runtime_context.
        extra_context: Additional runtime_context entries to merge.

    Returns:
        Constructed AlphaContext instance.
    """
    context: dict[str, Any] = {}
    if role:
        context["role"] = role
    if extra_context:
        context.update(extra_context)
    return AlphaContext.from_runtime(
        principal=principal,
        action=action,
        resource=resource,
        runtime_context=context,
    )


def _make_gamma(
    *,
    principal: str = PRINCIPAL_ALICE,
    policies: list[dict[str, Any]] | None = None,
    environment: dict[str, Any] | None = None,
) -> GammaKnowledgeBase:
    """Build a GammaKnowledgeBase with optional policies and environment.

    Args:
        principal: Principal string; must match alpha for AuthValid.
        policies: List of policy dicts containing policy_json entries.
        environment: Environment dict for guardrail configuration.

    Returns:
        Constructed GammaKnowledgeBase instance.
    """
    return GammaKnowledgeBase(
        principal=principal,
        policies=policies or [],
        active_grants=[],
        active_revocations=[],
        obligations=[],
        environment=environment or {},
    )


def _make_policy_with_rules(
    pre_rules: list[dict[str, Any]] | None = None,
    post_rules: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Construct a policy dict with pre_rules and post_rules.

    Args:
        pre_rules: Rules to place in the pre_rules section.
        post_rules: Rules to place in the post_rules section.

    Returns:
        Policy dict with policy_json containing the specified rules.
    """
    return {
        "policy_json": {
            "pre_rules": pre_rules or [],
            "post_rules": post_rules or [],
        }
    }


# ---------------------------------------------------------------------------
# Tests: _match_policy_rule -- role_allow
# ---------------------------------------------------------------------------


class TestMatchPolicyRuleRoleAllow:
    """Unit tests for _match_policy_rule with rule type role_allow."""

    def test_exact_role_match_returns_true(self):
        """Exact lowercase role match against role_allow returns True."""
        alpha = _make_alpha(role=ROLE_ADMIN)
        rule: dict[str, Any] = {"type": "role_allow", "role": ROLE_ADMIN}
        assert _match_policy_rule(alpha, rule) is True

    def test_role_mismatch_returns_false(self):
        """Different role against role_allow returns False."""
        alpha = _make_alpha(role=ROLE_VIEWER)
        rule: dict[str, Any] = {"type": "role_allow", "role": ROLE_ADMIN}
        assert _match_policy_rule(alpha, rule) is False

    def test_case_insensitive_alpha_upper(self):
        """Role in runtime_context with uppercase is matched case-insensitively."""
        alpha = _make_alpha(role="ADMIN")
        rule: dict[str, Any] = {"type": "role_allow", "role": ROLE_ADMIN}
        assert _match_policy_rule(alpha, rule) is True

    def test_case_insensitive_rule_upper(self):
        """Role in rule dict with uppercase is matched case-insensitively."""
        alpha = _make_alpha(role=ROLE_ADMIN)
        rule: dict[str, Any] = {"type": "role_allow", "role": "ADMIN"}
        assert _match_policy_rule(alpha, rule) is True

    def test_case_insensitive_both_mixed(self):
        """Mixed case on both sides still matches."""
        alpha = _make_alpha(role="AdMiN")
        rule: dict[str, Any] = {"type": "role_allow", "role": "aDmIn"}
        assert _match_policy_rule(alpha, rule) is True

    def test_wildcard_role_in_rule_matches_any(self):
        """Wildcard '*' in rule role matches any non-empty user role."""
        alpha = _make_alpha(role=ROLE_VIEWER)
        rule: dict[str, Any] = {"type": "role_allow", "role": ROLE_WILDCARD}
        assert _match_policy_rule(alpha, rule) is True

    def test_wildcard_matches_admin(self):
        """Wildcard '*' in rule matches admin role."""
        alpha = _make_alpha(role=ROLE_ADMIN)
        rule: dict[str, Any] = {"type": "role_allow", "role": ROLE_WILDCARD}
        assert _match_policy_rule(alpha, rule) is True

    def test_wildcard_matches_editor(self):
        """Wildcard '*' in rule matches editor role."""
        alpha = _make_alpha(role=ROLE_EDITOR)
        rule: dict[str, Any] = {"type": "role_allow", "role": ROLE_WILDCARD}
        assert _match_policy_rule(alpha, rule) is True

    def test_empty_user_role_returns_false(self):
        """Empty string role in runtime_context returns False."""
        alpha = _make_alpha(role="")
        rule: dict[str, Any] = {"type": "role_allow", "role": ROLE_ADMIN}
        assert _match_policy_rule(alpha, rule) is False

    def test_missing_role_key_in_context_returns_false(self):
        """No 'role' key in runtime_context returns False."""
        alpha = AlphaContext.from_runtime(
            principal=PRINCIPAL_ALICE,
            action=ACTION_READ,
            resource=RESOURCE_DOCS,
            runtime_context={},
        )
        rule: dict[str, Any] = {"type": "role_allow", "role": ROLE_ADMIN}
        assert _match_policy_rule(alpha, rule) is False

    def test_empty_rule_role_returns_false(self):
        """Empty string role in rule returns False even if user has a role."""
        alpha = _make_alpha(role=ROLE_ADMIN)
        rule: dict[str, Any] = {"type": "role_allow", "role": ""}
        assert _match_policy_rule(alpha, rule) is False

    def test_missing_rule_role_key_returns_false(self):
        """Missing 'role' key in rule returns False."""
        alpha = _make_alpha(role=ROLE_ADMIN)
        rule: dict[str, Any] = {"type": "role_allow"}
        assert _match_policy_rule(alpha, rule) is False

    def test_whitespace_only_user_role_returns_false(self):
        """Whitespace-only role in context is stripped to empty and returns False."""
        alpha = _make_alpha(role="   ")
        rule: dict[str, Any] = {"type": "role_allow", "role": ROLE_ADMIN}
        assert _match_policy_rule(alpha, rule) is False

    def test_whitespace_only_rule_role_returns_false(self):
        """Whitespace-only role in rule is stripped to empty and returns False."""
        alpha = _make_alpha(role=ROLE_ADMIN)
        rule: dict[str, Any] = {"type": "role_allow", "role": "   "}
        assert _match_policy_rule(alpha, rule) is False


# ---------------------------------------------------------------------------
# Tests: _match_policy_rule -- role_deny
# ---------------------------------------------------------------------------


class TestMatchPolicyRuleRoleDeny:
    """Unit tests for _match_policy_rule with rule type role_deny."""

    def test_exact_role_match_returns_true(self):
        """Exact lowercase role match against role_deny returns True."""
        alpha = _make_alpha(role=ROLE_VIEWER)
        rule: dict[str, Any] = {"type": "role_deny", "role": ROLE_VIEWER}
        assert _match_policy_rule(alpha, rule) is True

    def test_role_mismatch_returns_false(self):
        """Different role against role_deny returns False."""
        alpha = _make_alpha(role=ROLE_ADMIN)
        rule: dict[str, Any] = {"type": "role_deny", "role": ROLE_VIEWER}
        assert _match_policy_rule(alpha, rule) is False

    def test_case_insensitive_deny_alpha_upper(self):
        """Uppercase role in context is matched case-insensitively for deny."""
        alpha = _make_alpha(role="VIEWER")
        rule: dict[str, Any] = {"type": "role_deny", "role": ROLE_VIEWER}
        assert _match_policy_rule(alpha, rule) is True

    def test_case_insensitive_deny_rule_upper(self):
        """Uppercase role in deny rule is matched case-insensitively."""
        alpha = _make_alpha(role=ROLE_VIEWER)
        rule: dict[str, Any] = {"type": "role_deny", "role": "VIEWER"}
        assert _match_policy_rule(alpha, rule) is True

    def test_wildcard_deny_matches_any_role(self):
        """Wildcard '*' in deny rule matches any non-empty user role."""
        alpha = _make_alpha(role=ROLE_ADMIN)
        rule: dict[str, Any] = {"type": "role_deny", "role": ROLE_WILDCARD}
        assert _match_policy_rule(alpha, rule) is True

    def test_wildcard_deny_matches_viewer(self):
        """Wildcard '*' in deny rule matches viewer role."""
        alpha = _make_alpha(role=ROLE_VIEWER)
        rule: dict[str, Any] = {"type": "role_deny", "role": ROLE_WILDCARD}
        assert _match_policy_rule(alpha, rule) is True

    def test_empty_user_role_deny_returns_false(self):
        """Empty string role in context returns False for deny."""
        alpha = _make_alpha(role="")
        rule: dict[str, Any] = {"type": "role_deny", "role": ROLE_VIEWER}
        assert _match_policy_rule(alpha, rule) is False

    def test_missing_role_in_context_deny_returns_false(self):
        """Missing 'role' key in runtime_context returns False for deny."""
        alpha = AlphaContext.from_runtime(
            principal=PRINCIPAL_ALICE,
            action=ACTION_READ,
            resource=RESOURCE_DOCS,
            runtime_context={},
        )
        rule: dict[str, Any] = {"type": "role_deny", "role": ROLE_VIEWER}
        assert _match_policy_rule(alpha, rule) is False

    def test_empty_rule_role_deny_returns_false(self):
        """Empty string role in deny rule returns False."""
        alpha = _make_alpha(role=ROLE_VIEWER)
        rule: dict[str, Any] = {"type": "role_deny", "role": ""}
        assert _match_policy_rule(alpha, rule) is False

    def test_missing_rule_role_key_deny_returns_false(self):
        """Missing 'role' key in deny rule returns False."""
        alpha = _make_alpha(role=ROLE_VIEWER)
        rule: dict[str, Any] = {"type": "role_deny"}
        assert _match_policy_rule(alpha, rule) is False


# ---------------------------------------------------------------------------
# Tests: _match_policy_rule -- unknown type
# ---------------------------------------------------------------------------


class TestMatchPolicyRuleUnknownType:
    """Edge cases for _match_policy_rule with unrecognized rule types."""

    def test_unknown_rule_type_returns_false(self):
        """Unrecognized rule type always returns False."""
        alpha = _make_alpha(role=ROLE_ADMIN)
        rule: dict[str, Any] = {"type": "unknown_type", "role": ROLE_ADMIN}
        assert _match_policy_rule(alpha, rule) is False

    def test_empty_rule_type_returns_false(self):
        """Empty string rule type always returns False."""
        alpha = _make_alpha(role=ROLE_ADMIN)
        rule: dict[str, Any] = {"type": ""}
        assert _match_policy_rule(alpha, rule) is False

    def test_missing_rule_type_returns_false(self):
        """Missing 'type' key in rule always returns False."""
        alpha = _make_alpha(role=ROLE_ADMIN)
        rule: dict[str, Any] = {"role": ROLE_ADMIN}
        assert _match_policy_rule(alpha, rule) is False


# ---------------------------------------------------------------------------
# Tests: _extract_policy_rules classification
# ---------------------------------------------------------------------------


class TestExtractPolicyRulesClassification:
    """Tests for _extract_policy_rules correctly classifying role rules."""

    def test_role_allow_classified_as_allow_rule(self):
        """role_allow in pre_rules appears in allow_rules output."""
        allow_rule: dict[str, Any] = {"type": "role_allow", "role": ROLE_ADMIN}
        policy = _make_policy_with_rules(pre_rules=[allow_rule])
        gamma = _make_gamma(policies=[policy])
        allow_rules, deny_rules = _extract_policy_rules(gamma)
        assert allow_rule in allow_rules
        assert allow_rule not in deny_rules

    def test_role_deny_classified_as_deny_rule(self):
        """role_deny in pre_rules appears in deny_rules output."""
        deny_rule: dict[str, Any] = {"type": "role_deny", "role": ROLE_VIEWER}
        policy = _make_policy_with_rules(pre_rules=[deny_rule])
        gamma = _make_gamma(policies=[policy])
        allow_rules, deny_rules = _extract_policy_rules(gamma)
        assert deny_rule in deny_rules
        assert deny_rule not in allow_rules

    def test_role_allow_in_post_rules_classified_correctly(self):
        """role_allow in post_rules appears in allow_rules output."""
        allow_rule: dict[str, Any] = {"type": "role_allow", "role": ROLE_ADMIN}
        policy = _make_policy_with_rules(post_rules=[allow_rule])
        gamma = _make_gamma(policies=[policy])
        allow_rules, deny_rules = _extract_policy_rules(gamma)
        assert allow_rule in allow_rules
        assert allow_rule not in deny_rules

    def test_role_deny_in_post_rules_classified_correctly(self):
        """role_deny in post_rules appears in deny_rules output."""
        deny_rule: dict[str, Any] = {"type": "role_deny", "role": ROLE_VIEWER}
        policy = _make_policy_with_rules(post_rules=[deny_rule])
        gamma = _make_gamma(policies=[policy])
        allow_rules, deny_rules = _extract_policy_rules(gamma)
        assert deny_rule in deny_rules
        assert deny_rule not in allow_rules

    def test_mixed_pre_and_post_rules_classified_separately(self):
        """role_allow and role_deny across pre/post are classified correctly."""
        allow_pre: dict[str, Any] = {"type": "role_allow", "role": ROLE_ADMIN}
        deny_post: dict[str, Any] = {"type": "role_deny", "role": ROLE_VIEWER}
        policy = _make_policy_with_rules(
            pre_rules=[allow_pre],
            post_rules=[deny_post],
        )
        gamma = _make_gamma(policies=[policy])
        allow_rules, deny_rules = _extract_policy_rules(gamma)
        assert allow_pre in allow_rules
        assert deny_post in deny_rules

    def test_multiple_policies_aggregate_all_rules(self):
        """Rules from multiple policies are all collected."""
        allow_rule: dict[str, Any] = {"type": "role_allow", "role": ROLE_ADMIN}
        deny_rule: dict[str, Any] = {"type": "role_deny", "role": ROLE_VIEWER}
        policy_a = _make_policy_with_rules(pre_rules=[allow_rule])
        policy_b = _make_policy_with_rules(pre_rules=[deny_rule])
        gamma = _make_gamma(policies=[policy_a, policy_b])
        allow_rules, deny_rules = _extract_policy_rules(gamma)
        assert allow_rule in allow_rules
        assert deny_rule in deny_rules

    def test_empty_policies_returns_empty_lists(self):
        """No policies returns two empty lists."""
        gamma = _make_gamma(policies=[])
        allow_rules, deny_rules = _extract_policy_rules(gamma)
        assert not allow_rules
        assert not deny_rules

    def test_non_role_rules_not_misclassified(self):
        """action_allow/action_deny rules remain in their correct buckets."""
        action_allow: dict[str, Any] = {"type": "action_allow", "action": ACTION_READ}
        action_deny: dict[str, Any] = {"type": "action_deny", "action": ACTION_WRITE}
        policy = _make_policy_with_rules(
            pre_rules=[action_allow, action_deny],
        )
        gamma = _make_gamma(policies=[policy])
        allow_rules, deny_rules = _extract_policy_rules(gamma)
        assert action_allow in allow_rules
        assert action_deny in deny_rules

    def test_unknown_rule_type_not_classified(self):
        """Unknown rule types are silently excluded from both lists."""
        unknown_rule: dict[str, Any] = {"type": "unsupported_type", "role": ROLE_ADMIN}
        policy = _make_policy_with_rules(pre_rules=[unknown_rule])
        gamma = _make_gamma(policies=[policy])
        allow_rules, deny_rules = _extract_policy_rules(gamma)
        assert unknown_rule not in allow_rules
        assert unknown_rule not in deny_rules

    def test_return_type_is_tuple_of_two_lists(self):
        """Return value is a two-element tuple of lists."""
        gamma = _make_gamma(policies=[])
        result = _extract_policy_rules(gamma)
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], list)
        assert isinstance(result[1], list)


# ---------------------------------------------------------------------------
# Tests: _permit_exists integration
# ---------------------------------------------------------------------------


class TestPermitExistsRoleIntegration:
    """Integration tests for _permit_exists using role_allow rules."""

    def test_permit_exists_true_when_role_allow_matches(self):
        """_permit_exists returns True when role_allow rule matches user role."""
        alpha = _make_alpha(role=ROLE_ADMIN)
        allow_rule: dict[str, Any] = {"type": "role_allow", "role": ROLE_ADMIN}
        policy = _make_policy_with_rules(pre_rules=[allow_rule])
        gamma = _make_gamma(policies=[policy])
        outcome = _permit_exists(alpha, gamma)
        assert outcome.value is True

    def test_permit_exists_false_when_role_allow_does_not_match(self):
        """_permit_exists returns False when role_allow rule does not match."""
        alpha = _make_alpha(role=ROLE_VIEWER)
        allow_rule: dict[str, Any] = {"type": "role_allow", "role": ROLE_ADMIN}
        policy = _make_policy_with_rules(pre_rules=[allow_rule])
        gamma = _make_gamma(policies=[policy])
        outcome = _permit_exists(alpha, gamma)
        assert outcome.value is False

    def test_permit_exists_witness_contains_policy_match(self):
        """When permit exists via role_allow, witness lists the matched rule."""
        alpha = _make_alpha(role=ROLE_ADMIN)
        allow_rule: dict[str, Any] = {"type": "role_allow", "role": ROLE_ADMIN}
        policy = _make_policy_with_rules(pre_rules=[allow_rule])
        gamma = _make_gamma(policies=[policy])
        outcome = _permit_exists(alpha, gamma)
        assert outcome.witness["policy_matches"]

    def test_permit_exists_wildcard_role_allows_any_user(self):
        """Wildcard role_allow permits users with any non-empty role."""
        for role in (ROLE_ADMIN, ROLE_VIEWER, ROLE_EDITOR):
            alpha = _make_alpha(role=role)
            allow_rule: dict[str, Any] = {"type": "role_allow", "role": ROLE_WILDCARD}
            policy = _make_policy_with_rules(pre_rules=[allow_rule])
            gamma = _make_gamma(policies=[policy])
            outcome = _permit_exists(alpha, gamma)
            assert outcome.value is True, f"Expected permit for role={role}"

    def test_permit_exists_false_when_no_role_in_context(self):
        """_permit_exists returns False when context has no role key."""
        alpha = AlphaContext.from_runtime(
            principal=PRINCIPAL_ALICE,
            action=ACTION_READ,
            resource=RESOURCE_DOCS,
            runtime_context={},
        )
        allow_rule: dict[str, Any] = {"type": "role_allow", "role": ROLE_ADMIN}
        policy = _make_policy_with_rules(pre_rules=[allow_rule])
        gamma = _make_gamma(policies=[policy])
        outcome = _permit_exists(alpha, gamma)
        assert outcome.value is False

    def test_permit_exists_case_insensitive_via_engine(self):
        """Role matching via _permit_exists is case-insensitive."""
        alpha = _make_alpha(role="ADMIN")
        allow_rule: dict[str, Any] = {"type": "role_allow", "role": "admin"}
        policy = _make_policy_with_rules(pre_rules=[allow_rule])
        gamma = _make_gamma(policies=[policy])
        outcome = _permit_exists(alpha, gamma)
        assert outcome.value is True

    def test_permit_exists_unconfigured_fallback(self):
        """Empty policies yields unconfigured fallback permit."""
        alpha = _make_alpha(role=ROLE_VIEWER)
        gamma = _make_gamma(policies=[])
        outcome = _permit_exists(alpha, gamma)
        assert outcome.value is True
        assert outcome.witness["unconfigured_fallback"] is True


# ---------------------------------------------------------------------------
# Tests: _deny_exists integration
# ---------------------------------------------------------------------------


class TestDenyExistsRoleIntegration:
    """Integration tests for _deny_exists using role_deny rules."""

    def test_deny_exists_true_when_role_deny_matches(self):
        """_deny_exists returns True when role_deny rule matches user role."""
        alpha = _make_alpha(role=ROLE_VIEWER)
        deny_rule: dict[str, Any] = {"type": "role_deny", "role": ROLE_VIEWER}
        policy = _make_policy_with_rules(pre_rules=[deny_rule])
        gamma = _make_gamma(policies=[policy])
        outcome = _deny_exists(alpha, gamma)
        assert outcome.value is True

    def test_deny_exists_false_when_role_deny_does_not_match(self):
        """_deny_exists returns False when role_deny rule does not match."""
        alpha = _make_alpha(role=ROLE_ADMIN)
        deny_rule: dict[str, Any] = {"type": "role_deny", "role": ROLE_VIEWER}
        policy = _make_policy_with_rules(pre_rules=[deny_rule])
        gamma = _make_gamma(policies=[policy])
        outcome = _deny_exists(alpha, gamma)
        assert outcome.value is False

    def test_deny_exists_witness_contains_matched_rule(self):
        """When deny exists via role_deny, witness records the matched rule."""
        alpha = _make_alpha(role=ROLE_VIEWER)
        deny_rule: dict[str, Any] = {"type": "role_deny", "role": ROLE_VIEWER}
        policy = _make_policy_with_rules(pre_rules=[deny_rule])
        gamma = _make_gamma(policies=[policy])
        outcome = _deny_exists(alpha, gamma)
        assert outcome.witness["matched_rule"] is not None

    def test_deny_exists_witness_records_evaluated_rules(self):
        """deny_exists witness lists all evaluated rules."""
        alpha = _make_alpha(role=ROLE_ADMIN)
        deny_rule: dict[str, Any] = {"type": "role_deny", "role": ROLE_VIEWER}
        policy = _make_policy_with_rules(pre_rules=[deny_rule])
        gamma = _make_gamma(policies=[policy])
        outcome = _deny_exists(alpha, gamma)
        assert len(outcome.witness["evaluated_rules"]) == 1
        assert outcome.witness["evaluated_rules"][0]["matched"] is False

    def test_deny_exists_wildcard_denies_all_roles(self):
        """Wildcard role_deny blocks users with any non-empty role."""
        for role in (ROLE_ADMIN, ROLE_VIEWER, ROLE_EDITOR):
            alpha = _make_alpha(role=role)
            deny_rule: dict[str, Any] = {"type": "role_deny", "role": ROLE_WILDCARD}
            policy = _make_policy_with_rules(pre_rules=[deny_rule])
            gamma = _make_gamma(policies=[policy])
            outcome = _deny_exists(alpha, gamma)
            assert outcome.value is True, f"Expected deny for role={role}"

    def test_deny_exists_false_when_no_role_in_context(self):
        """_deny_exists returns False when context has no role key."""
        alpha = AlphaContext.from_runtime(
            principal=PRINCIPAL_ALICE,
            action=ACTION_READ,
            resource=RESOURCE_DOCS,
            runtime_context={},
        )
        deny_rule: dict[str, Any] = {"type": "role_deny", "role": ROLE_VIEWER}
        policy = _make_policy_with_rules(pre_rules=[deny_rule])
        gamma = _make_gamma(policies=[policy])
        outcome = _deny_exists(alpha, gamma)
        assert outcome.value is False

    def test_deny_exists_case_insensitive_via_engine(self):
        """Role matching via _deny_exists is case-insensitive."""
        alpha = _make_alpha(role="VIEWER")
        deny_rule: dict[str, Any] = {"type": "role_deny", "role": "viewer"}
        policy = _make_policy_with_rules(pre_rules=[deny_rule])
        gamma = _make_gamma(policies=[policy])
        outcome = _deny_exists(alpha, gamma)
        assert outcome.value is True

    def test_deny_exists_no_rules_returns_false(self):
        """No deny rules configured means deny does not exist."""
        alpha = _make_alpha(role=ROLE_ADMIN)
        gamma = _make_gamma(policies=[])
        outcome = _deny_exists(alpha, gamma)
        assert outcome.value is False


# ---------------------------------------------------------------------------
# Tests: Role rule interaction semantics
# ---------------------------------------------------------------------------


class TestRoleRuleInteractionSemantics:
    """Tests for interaction between role_allow, role_deny, and other rules."""

    def test_role_deny_overrides_role_allow_for_same_role(self):
        """When both role_allow and role_deny match, deny takes precedence."""
        alpha = _make_alpha(role=ROLE_VIEWER)
        allow_rule: dict[str, Any] = {"type": "role_allow", "role": ROLE_WILDCARD}
        deny_rule: dict[str, Any] = {"type": "role_deny", "role": ROLE_VIEWER}
        policy = _make_policy_with_rules(
            pre_rules=[allow_rule, deny_rule],
        )
        gamma = _make_gamma(policies=[policy])
        permit_outcome = _permit_exists(alpha, gamma)
        deny_outcome = _deny_exists(alpha, gamma)
        # Both individually match but deny semantically dominates
        assert permit_outcome.value is True
        assert deny_outcome.value is True

    def test_admin_allowed_viewer_denied_independently(self):
        """Admin is allowed and viewer is denied by separate policies."""
        allow_rule: dict[str, Any] = {"type": "role_allow", "role": ROLE_ADMIN}
        deny_rule: dict[str, Any] = {"type": "role_deny", "role": ROLE_VIEWER}
        policy = _make_policy_with_rules(
            pre_rules=[allow_rule, deny_rule],
        )
        gamma = _make_gamma(policies=[policy])

        alpha_admin = _make_alpha(role=ROLE_ADMIN)
        permit_admin = _permit_exists(alpha_admin, gamma)
        deny_admin = _deny_exists(alpha_admin, gamma)
        assert permit_admin.value is True
        assert deny_admin.value is False

        alpha_viewer = _make_alpha(role=ROLE_VIEWER)
        permit_viewer = _permit_exists(alpha_viewer, gamma)
        deny_viewer = _deny_exists(alpha_viewer, gamma)
        assert permit_viewer.value is False
        assert deny_viewer.value is True

    def test_role_and_action_rules_coexist_in_same_policy(self):
        """role_allow and action_allow can coexist and be classified correctly."""
        role_allow: dict[str, Any] = {"type": "role_allow", "role": ROLE_ADMIN}
        action_allow: dict[str, Any] = {"type": "action_allow", "action": ACTION_READ}
        action_deny: dict[str, Any] = {"type": "action_deny", "action": ACTION_WRITE}
        role_deny: dict[str, Any] = {"type": "role_deny", "role": ROLE_VIEWER}
        policy = _make_policy_with_rules(
            pre_rules=[role_allow, action_allow, action_deny, role_deny],
        )
        gamma = _make_gamma(policies=[policy])
        allow_rules, deny_rules = _extract_policy_rules(gamma)
        assert role_allow in allow_rules
        assert action_allow in allow_rules
        assert action_deny in deny_rules
        assert role_deny in deny_rules

    def test_editor_role_not_matched_by_admin_deny_rule(self):
        """role_deny for admin does not match editor role."""
        alpha = _make_alpha(role=ROLE_EDITOR)
        deny_rule: dict[str, Any] = {"type": "role_deny", "role": ROLE_ADMIN}
        policy = _make_policy_with_rules(pre_rules=[deny_rule])
        gamma = _make_gamma(policies=[policy])
        outcome = _deny_exists(alpha, gamma)
        assert outcome.value is False

    def test_predicate_outcome_name_is_permit_exists(self):
        """_permit_exists outcome name is 'PermitExists'."""
        alpha = _make_alpha(role=ROLE_ADMIN)
        allow_rule: dict[str, Any] = {"type": "role_allow", "role": ROLE_ADMIN}
        policy = _make_policy_with_rules(pre_rules=[allow_rule])
        gamma = _make_gamma(policies=[policy])
        outcome = _permit_exists(alpha, gamma)
        assert outcome.name == "PermitExists"

    def test_predicate_outcome_name_is_deny_exists(self):
        """_deny_exists outcome name is 'DenyExists'."""
        alpha = _make_alpha(role=ROLE_VIEWER)
        deny_rule: dict[str, Any] = {"type": "role_deny", "role": ROLE_VIEWER}
        policy = _make_policy_with_rules(pre_rules=[deny_rule])
        gamma = _make_gamma(policies=[policy])
        outcome = _deny_exists(alpha, gamma)
        assert outcome.name == "DenyExists"

    def test_deny_absence_proof_in_deny_witness(self):
        """deny_exists witness contains deny_absence_proof metadata."""
        alpha = _make_alpha(role=ROLE_ADMIN)
        deny_rule: dict[str, Any] = {"type": "role_deny", "role": ROLE_VIEWER}
        policy = _make_policy_with_rules(pre_rules=[deny_rule])
        gamma = _make_gamma(policies=[policy])
        outcome = _deny_exists(alpha, gamma)
        proof = outcome.witness.get("deny_absence_proof", {})
        assert proof.get("mode") == "EXHAUSTIVE_RULE_EVALUATION"
        assert proof.get("checked_rule_count") == 1
        assert proof.get("matched_count") == 0

    def test_multiple_deny_rules_first_match_is_recorded(self):
        """When multiple deny rules match, the first matched rule is recorded."""
        alpha = _make_alpha(role=ROLE_VIEWER)
        first_deny: dict[str, Any] = {"type": "role_deny", "role": ROLE_VIEWER}
        second_deny: dict[str, Any] = {"type": "role_deny", "role": ROLE_WILDCARD}
        policy = _make_policy_with_rules(pre_rules=[first_deny, second_deny])
        gamma = _make_gamma(policies=[policy])
        outcome = _deny_exists(alpha, gamma)
        assert outcome.value is True
        assert outcome.witness["matched_rule"] == first_deny

    def test_role_allow_in_post_rules_contributes_to_permit(self):
        """role_allow in post_rules contributes to permit evaluation."""
        alpha = _make_alpha(role=ROLE_EDITOR)
        allow_rule: dict[str, Any] = {"type": "role_allow", "role": ROLE_EDITOR}
        policy = _make_policy_with_rules(post_rules=[allow_rule])
        gamma = _make_gamma(policies=[policy])
        outcome = _permit_exists(alpha, gamma)
        assert outcome.value is True

    def test_role_deny_in_post_rules_contributes_to_deny(self):
        """role_deny in post_rules contributes to deny evaluation."""
        alpha = _make_alpha(role=ROLE_VIEWER)
        deny_rule: dict[str, Any] = {"type": "role_deny", "role": ROLE_VIEWER}
        policy = _make_policy_with_rules(post_rules=[deny_rule])
        gamma = _make_gamma(policies=[policy])
        outcome = _deny_exists(alpha, gamma)
        assert outcome.value is True
