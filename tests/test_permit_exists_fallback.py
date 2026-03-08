"""Tests for _permit_exists unconfigured fallback and direct_permit=False default.

Covers the behavior matrix for permit evaluation including:
- Unconfigured system (no policies, no grants) -- fail-open via unconfigured_fallback
- Matching allow rules -- ADMISSIBLE via policy_matches
- Non-matching rules with policies present -- INADMISSIBLE
- Explicit direct_permit=True -- ADMISSIBLE via direct_permit flag
- direct_permit=False default via _normalize_runtime_context
- Grant-based permit evaluation

Extended coverage (deny and interaction tests) lives in
``tests/test_deny_exists_and_interactions.py``.
"""

# ---------------------------------------------------------------------------
# Standard Library
# ---------------------------------------------------------------------------
from typing import Any

from server.policy_governance.kernel.enforcement import _normalize_runtime_context
from server.policy_governance.kernel.formal_models import (
    AlphaContext,
    GammaKnowledgeBase,
)

# ---------------------------------------------------------------------------
# Local / Application
# ---------------------------------------------------------------------------
from server.policy_governance.kernel.solver_engine import _permit_exists

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PRINCIPAL = "agent:test-agent"
ACTION = "read"
RESOURCE = "data/reports"
TENANT = "tenant-alpha"

_ALLOW_ACTION_RULE: dict[str, Any] = {"type": "action_allow", "action": "read"}
_DENY_ACTION_RULE: dict[str, Any] = {"type": "action_deny", "action": "read"}
_ALLOW_PERMIT_RULE: dict[str, Any] = {
    "type": "permit",
    "action": "read",
    "resource": "data/reports",
}
_ROLE_ALLOW_RULE: dict[str, Any] = {"type": "role_allow", "role": "developer"}
_ALLOW_WILDCARD_RULE: dict[str, Any] = {"type": "action_allow", "action": "*"}

_GRANT_READ_REPORTS: dict[str, Any] = {
    "grant_id": "grant-001",
    "allowed_actions": ["read"],
    "resource_scope": "data/reports",
}
_GRANT_WILDCARD: dict[str, Any] = {
    "grant_id": "grant-wildcard",
    "allowed_actions": ["*"],
    "resource_scope": "*",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _make_alpha(
    runtime_context: dict[str, Any] | None = None,
    action: str = ACTION,
    resource: str = RESOURCE,
) -> AlphaContext:
    """Construct an AlphaContext for the standard test principal.

    Args:
        runtime_context: Optional runtime context dict. Defaults to empty.
        action: The action identifier. Defaults to ACTION constant.
        resource: The resource identifier. Defaults to RESOURCE constant.

    Returns:
        A fully constructed AlphaContext with deterministic context hash.
    """
    return AlphaContext.from_runtime(
        principal=PRINCIPAL,
        action=action,
        resource=resource,
        runtime_context=runtime_context or {},
        tenant_id=TENANT,
    )


def _make_gamma(
    policies: list[dict[str, Any]] | None = None,
    active_grants: list[dict[str, Any]] | None = None,
    environment: dict[str, Any] | None = None,
) -> GammaKnowledgeBase:
    """Construct a GammaKnowledgeBase with the standard test principal.

    Args:
        policies: List of policy dicts containing policy_json. Defaults to [].
        active_grants: List of grant dicts. Defaults to [].
        environment: Environment dict (e.g. blocked_operations). Defaults to {}.

    Returns:
        A GammaKnowledgeBase instance with a computed gamma_hash.
    """
    kb = GammaKnowledgeBase(
        principal=PRINCIPAL,
        tenant_id=TENANT,
        policies=policies or [],
        active_grants=active_grants or [],
        environment=environment or {},
    )
    kb.compute_gamma_hash()
    return kb


def _policy_with_pre_rules(rules: list[dict[str, Any]]) -> dict[str, Any]:
    """Wrap a list of pre_rules into a policy record dict.

    Args:
        rules: List of rule dicts to place under pre_rules.

    Returns:
        A policy record dict with rules nested under policy_json.pre_rules.
    """
    return {"policy_json": {"pre_rules": rules, "post_rules": []}}


def _policy_with_post_rules(rules: list[dict[str, Any]]) -> dict[str, Any]:
    """Wrap a list of post_rules into a policy record dict.

    Args:
        rules: List of rule dicts to place under post_rules.

    Returns:
        A policy record dict with rules nested under policy_json.post_rules.
    """
    return {"policy_json": {"pre_rules": [], "post_rules": rules}}


# ---------------------------------------------------------------------------
# Tests: _normalize_runtime_context direct_permit default
# ---------------------------------------------------------------------------
class TestNormalizeRuntimeContextDefaults:
    """Verify that _normalize_runtime_context sets deterministic safe defaults."""

    def test_direct_permit_defaults_to_false_on_empty_input(self) -> None:
        """direct_permit must default to False when context is None."""
        result = _normalize_runtime_context(None)
        assert result["direct_permit"] is False

    def test_direct_permit_defaults_to_false_on_empty_dict(self) -> None:
        """direct_permit must default to False when context is an empty dict."""
        result = _normalize_runtime_context({})
        assert result["direct_permit"] is False

    def test_direct_permit_preserved_when_true(self) -> None:
        """direct_permit=True must survive normalization unchanged."""
        result = _normalize_runtime_context({"direct_permit": True})
        assert result["direct_permit"] is True

    def test_direct_permit_preserved_when_false_explicit(self) -> None:
        """Explicit direct_permit=False must survive normalization unchanged."""
        result = _normalize_runtime_context({"direct_permit": False})
        assert result["direct_permit"] is False

    def test_authenticated_defaults_to_true(self) -> None:
        """authenticated must default to True when absent."""
        result = _normalize_runtime_context(None)
        assert result["authenticated"] is True

    def test_direct_access_defaults_to_true(self) -> None:
        """direct_access must default to True when absent."""
        result = _normalize_runtime_context(None)
        assert result["direct_access"] is True

    def test_execution_phase_defaults_to_confirm(self) -> None:
        """execution_phase must default to 'confirm' when absent."""
        result = _normalize_runtime_context(None)
        assert result["execution_phase"] == "confirm"

    def test_preview_confirmed_defaults_to_true(self) -> None:
        """preview_confirmed must default to True when absent."""
        result = _normalize_runtime_context(None)
        assert result["preview_confirmed"] is True

    def test_existing_keys_not_overwritten(self) -> None:
        """Keys already present in context must not be overwritten by defaults."""
        context: dict[str, Any] = {
            "authenticated": False,
            "execution_phase": "preview",
        }
        result = _normalize_runtime_context(context)
        assert result["authenticated"] is False
        assert result["execution_phase"] == "preview"

    def test_extra_keys_are_preserved(self) -> None:
        """Extra caller-supplied keys must be retained in normalized output."""
        result = _normalize_runtime_context({"role": "developer", "source_ip": "10.0.0.1"})
        assert result["role"] == "developer"
        assert result["source_ip"] == "10.0.0.1"

    def test_returns_new_dict_not_mutating_input(self) -> None:
        """Normalization must not mutate the original caller-supplied dict."""
        original: dict[str, Any] = {"role": "admin"}
        result = _normalize_runtime_context(original)
        assert "direct_permit" not in original
        assert "direct_permit" in result


# ---------------------------------------------------------------------------
# Tests: _permit_exists unconfigured fallback
# ---------------------------------------------------------------------------
class TestPermitExistsUnconfiguredFallback:
    """Verify that an unconfigured system (no policies, no grants) fails open."""

    def test_no_policies_no_grants_is_admissible(self) -> None:
        """System with no policies and no grants must evaluate to ADMISSIBLE."""
        alpha = _make_alpha()
        gamma = _make_gamma()

        outcome = _permit_exists(alpha, gamma)

        assert outcome.value is True

    def test_unconfigured_fallback_witness_is_true(self) -> None:
        """Witness must record unconfigured_fallback=True for a bare system."""
        alpha = _make_alpha()
        gamma = _make_gamma()

        outcome = _permit_exists(alpha, gamma)

        assert outcome.witness["unconfigured_fallback"] is True

    def test_unconfigured_fallback_has_no_policy_matches(self) -> None:
        """Witness must show empty policy_matches when system is unconfigured."""
        alpha = _make_alpha()
        gamma = _make_gamma()

        outcome = _permit_exists(alpha, gamma)

        assert not outcome.witness["policy_matches"]

    def test_unconfigured_fallback_has_no_grant_matches(self) -> None:
        """Witness must show empty grant_matches when system is unconfigured."""
        alpha = _make_alpha()
        gamma = _make_gamma()

        outcome = _permit_exists(alpha, gamma)

        assert not outcome.witness["grant_matches"]

    def test_unconfigured_fallback_direct_permit_is_false(self) -> None:
        """Witness must record direct_permit=False on a bare unconfigured system."""
        alpha = _make_alpha()
        gamma = _make_gamma()

        outcome = _permit_exists(alpha, gamma)

        assert outcome.witness["direct_permit"] is False

    def test_predicate_name_is_permit_exists(self) -> None:
        """Predicate name on outcome must always be 'PermitExists'."""
        alpha = _make_alpha()
        gamma = _make_gamma()

        outcome = _permit_exists(alpha, gamma)

        assert outcome.name == "PermitExists"

    def test_unconfigured_holds_regardless_of_action(self) -> None:
        """Unconfigured fallback must apply regardless of the requested action."""
        alpha = _make_alpha(action="delete")
        gamma = _make_gamma()

        outcome = _permit_exists(alpha, gamma)

        assert outcome.value is True
        assert outcome.witness["unconfigured_fallback"] is True

    def test_unconfigured_holds_regardless_of_resource(self) -> None:
        """Unconfigured fallback must apply regardless of the requested resource."""
        alpha = _make_alpha(resource="secrets/vault")
        gamma = _make_gamma()

        outcome = _permit_exists(alpha, gamma)

        assert outcome.value is True
        assert outcome.witness["unconfigured_fallback"] is True


# ---------------------------------------------------------------------------
# Tests: _permit_exists with policies present -- matching allow rule
# ---------------------------------------------------------------------------
class TestPermitExistsPolicyAllowMatch:
    """Verify ADMISSIBLE outcome when a matching allow rule is present."""

    def test_action_allow_rule_match_is_admissible(self) -> None:
        """Matching action_allow rule must produce ADMISSIBLE outcome."""
        alpha = _make_alpha()
        gamma = _make_gamma(policies=[_policy_with_pre_rules([_ALLOW_ACTION_RULE])])

        outcome = _permit_exists(alpha, gamma)

        assert outcome.value is True

    def test_action_allow_match_has_policy_matches(self) -> None:
        """Witness must contain a non-empty policy_matches list on a rule match."""
        alpha = _make_alpha()
        gamma = _make_gamma(policies=[_policy_with_pre_rules([_ALLOW_ACTION_RULE])])

        outcome = _permit_exists(alpha, gamma)

        assert len(outcome.witness["policy_matches"]) == 1

    def test_action_allow_match_unconfigured_is_false(self) -> None:
        """Witness must record unconfigured_fallback=False when policies are set."""
        alpha = _make_alpha()
        gamma = _make_gamma(policies=[_policy_with_pre_rules([_ALLOW_ACTION_RULE])])

        outcome = _permit_exists(alpha, gamma)

        assert outcome.witness["unconfigured_fallback"] is False

    def test_permit_rule_with_matching_resource_is_admissible(self) -> None:
        """Permit rule that matches both action and resource must be ADMISSIBLE."""
        alpha = _make_alpha()
        gamma = _make_gamma(policies=[_policy_with_pre_rules([_ALLOW_PERMIT_RULE])])

        outcome = _permit_exists(alpha, gamma)

        assert outcome.value is True
        assert not outcome.witness["unconfigured_fallback"]

    def test_wildcard_action_allow_rule_is_admissible(self) -> None:
        """Wildcard action_allow rule must match any action."""
        alpha = _make_alpha(action="write")
        gamma = _make_gamma(policies=[_policy_with_pre_rules([_ALLOW_WILDCARD_RULE])])

        outcome = _permit_exists(alpha, gamma)

        assert outcome.value is True

    def test_post_rule_allow_match_is_admissible(self) -> None:
        """Allow rule in post_rules must produce ADMISSIBLE outcome."""
        post_allow: dict[str, Any] = {"type": "action_allow", "action": "read"}
        alpha = _make_alpha()
        gamma = _make_gamma(policies=[_policy_with_post_rules([post_allow])])

        outcome = _permit_exists(alpha, gamma)

        assert outcome.value is True

    def test_role_allow_rule_match_is_admissible(self) -> None:
        """Role_allow rule matching caller role must be ADMISSIBLE."""
        alpha = _make_alpha(runtime_context={"role": "developer"})
        gamma = _make_gamma(policies=[_policy_with_pre_rules([_ROLE_ALLOW_RULE])])

        outcome = _permit_exists(alpha, gamma)

        assert outcome.value is True

    def test_role_allow_wildcard_role_match_is_admissible(self) -> None:
        """Role_allow rule with role='*' must match any caller role."""
        rule: dict[str, Any] = {"type": "role_allow", "role": "*"}
        alpha = _make_alpha(runtime_context={"role": "admin"})
        gamma = _make_gamma(policies=[_policy_with_pre_rules([rule])])

        outcome = _permit_exists(alpha, gamma)

        assert outcome.value is True

    def test_multiple_policies_one_matching_rule_is_admissible(self) -> None:
        """At least one matching allow rule across multiple policies suffices."""
        non_matching: dict[str, Any] = {"type": "action_allow", "action": "write"}
        alpha = _make_alpha()
        policies = [
            _policy_with_pre_rules([non_matching]),
            _policy_with_pre_rules([_ALLOW_ACTION_RULE]),
        ]
        gamma = _make_gamma(policies=policies)

        outcome = _permit_exists(alpha, gamma)

        assert outcome.value is True


# ---------------------------------------------------------------------------
# Tests: _permit_exists with policies present -- no matching allow rule
# ---------------------------------------------------------------------------
class TestPermitExistsPolicyNoMatch:
    """Verify INADMISSIBLE outcome when policies exist but no allow rule matches."""

    def test_policy_present_wrong_action_is_inadmissible(self) -> None:
        """Action_allow for a different action must not match the caller's action."""
        other_rule: dict[str, Any] = {"type": "action_allow", "action": "write"}
        alpha = _make_alpha()  # action=read
        gamma = _make_gamma(policies=[_policy_with_pre_rules([other_rule])])

        outcome = _permit_exists(alpha, gamma)

        assert outcome.value is False

    def test_policy_present_wrong_action_witness_empty(self) -> None:
        """Witness policy_matches must be empty when no rule matches."""
        other_rule: dict[str, Any] = {"type": "action_allow", "action": "write"}
        alpha = _make_alpha()
        gamma = _make_gamma(policies=[_policy_with_pre_rules([other_rule])])

        outcome = _permit_exists(alpha, gamma)

        assert not outcome.witness["policy_matches"]

    def test_policy_present_wrong_action_unconfigured_false(self) -> None:
        """Witness must record unconfigured_fallback=False when policies exist."""
        other_rule: dict[str, Any] = {"type": "action_allow", "action": "write"}
        alpha = _make_alpha()
        gamma = _make_gamma(policies=[_policy_with_pre_rules([other_rule])])

        outcome = _permit_exists(alpha, gamma)

        assert outcome.witness["unconfigured_fallback"] is False

    def test_permit_rule_wrong_resource_is_inadmissible(self) -> None:
        """Permit rule for a different resource must not match."""
        rule: dict[str, Any] = {
            "type": "permit",
            "action": "read",
            "resource": "other/resource",
        }
        alpha = _make_alpha()  # resource=data/reports
        gamma = _make_gamma(policies=[_policy_with_pre_rules([rule])])

        outcome = _permit_exists(alpha, gamma)

        assert outcome.value is False

    def test_deny_only_policy_is_inadmissible(self) -> None:
        """Policy with only deny rules produces no allow matches -- INADMISSIBLE."""
        alpha = _make_alpha()
        gamma = _make_gamma(policies=[_policy_with_pre_rules([_DENY_ACTION_RULE])])

        outcome = _permit_exists(alpha, gamma)

        assert outcome.value is False

    def test_role_allow_rule_wrong_role_is_inadmissible(self) -> None:
        """Role_allow rule that does not match caller role must not grant permit."""
        alpha = _make_alpha(runtime_context={"role": "auditor"})
        gamma = _make_gamma(policies=[_policy_with_pre_rules([_ROLE_ALLOW_RULE])])

        outcome = _permit_exists(alpha, gamma)

        assert outcome.value is False

    def test_empty_role_in_context_role_allow_is_inadmissible(self) -> None:
        """Missing role in runtime context must not match a role_allow rule."""
        alpha = _make_alpha(runtime_context={})
        gamma = _make_gamma(policies=[_policy_with_pre_rules([_ROLE_ALLOW_RULE])])

        outcome = _permit_exists(alpha, gamma)

        assert outcome.value is False

    def test_multiple_policies_no_matching_rules_is_inadmissible(self) -> None:
        """Multiple policies all with non-matching rules must yield INADMISSIBLE."""
        wrong_rule_a: dict[str, Any] = {"type": "action_allow", "action": "write"}
        wrong_rule_b: dict[str, Any] = {"type": "action_allow", "action": "delete"}
        alpha = _make_alpha()
        policies = [
            _policy_with_pre_rules([wrong_rule_a]),
            _policy_with_pre_rules([wrong_rule_b]),
        ]
        gamma = _make_gamma(policies=policies)

        outcome = _permit_exists(alpha, gamma)

        assert outcome.value is False


# ---------------------------------------------------------------------------
# Tests: _permit_exists with active grants
# ---------------------------------------------------------------------------
class TestPermitExistsGrantMatch:
    """Verify ADMISSIBLE outcome when active grants cover the requested action."""

    def test_matching_grant_with_no_policies_is_admissible(self) -> None:
        """Grant matching action+resource must yield ADMISSIBLE without policies."""
        alpha = _make_alpha()
        gamma = _make_gamma(active_grants=[_GRANT_READ_REPORTS])

        outcome = _permit_exists(alpha, gamma)

        assert outcome.value is True

    def test_matching_grant_witness_grant_id(self) -> None:
        """Witness grant_matches must list the matched grant_id."""
        alpha = _make_alpha()
        gamma = _make_gamma(active_grants=[_GRANT_READ_REPORTS])

        outcome = _permit_exists(alpha, gamma)

        assert "grant-001" in outcome.witness["grant_matches"]

    def test_matching_grant_unconfigured_is_false(self) -> None:
        """Witness must record unconfigured_fallback=False when grants exist."""
        alpha = _make_alpha()
        gamma = _make_gamma(active_grants=[_GRANT_READ_REPORTS])

        outcome = _permit_exists(alpha, gamma)

        assert outcome.witness["unconfigured_fallback"] is False

    def test_wildcard_grant_matches_any_action(self) -> None:
        """Grant with allowed_actions=['*'] must match any action."""
        alpha = _make_alpha(action="delete")
        gamma = _make_gamma(active_grants=[_GRANT_WILDCARD])

        outcome = _permit_exists(alpha, gamma)

        assert outcome.value is True

    def test_grant_wrong_action_is_inadmissible(self) -> None:
        """Grant that does not cover the requested action must not match."""
        write_grant: dict[str, Any] = {
            "grant_id": "grant-write",
            "allowed_actions": ["write"],
            "resource_scope": "*",
        }
        alpha = _make_alpha()  # action=read
        gamma = _make_gamma(active_grants=[write_grant])

        outcome = _permit_exists(alpha, gamma)

        assert outcome.value is False

    def test_grant_wrong_resource_scope_is_inadmissible(self) -> None:
        """Grant with non-matching resource_scope must not match."""
        scoped_grant: dict[str, Any] = {
            "grant_id": "grant-scoped",
            "allowed_actions": ["read"],
            "resource_scope": "data/other",
        }
        alpha = _make_alpha()  # resource=data/reports
        gamma = _make_gamma(active_grants=[scoped_grant])

        outcome = _permit_exists(alpha, gamma)

        assert outcome.value is False

    def test_grant_prefix_scope_matches_resource(self) -> None:
        """Grant resource_scope with wildcard prefix must match nested resources."""
        prefix_grant: dict[str, Any] = {
            "grant_id": "grant-prefix",
            "allowed_actions": ["read"],
            "resource_scope": "data/*",
        }
        alpha = _make_alpha()  # resource=data/reports
        gamma = _make_gamma(active_grants=[prefix_grant])

        outcome = _permit_exists(alpha, gamma)

        assert outcome.value is True


# ---------------------------------------------------------------------------
# Tests: _permit_exists with direct_permit=True
# ---------------------------------------------------------------------------
class TestPermitExistsDirectPermit:
    """Verify that an explicit direct_permit=True flag in runtime context allows."""

    def test_direct_permit_true_no_policies_no_grants_is_admissible(self) -> None:
        """direct_permit=True must grant ADMISSIBLE even with no policies or grants."""
        alpha = _make_alpha(runtime_context={"direct_permit": True})
        gamma = _make_gamma()

        outcome = _permit_exists(alpha, gamma)

        assert outcome.value is True

    def test_direct_permit_true_witness_flag_is_true(self) -> None:
        """Witness direct_permit must be True when explicitly set."""
        alpha = _make_alpha(runtime_context={"direct_permit": True})
        gamma = _make_gamma()

        outcome = _permit_exists(alpha, gamma)

        assert outcome.witness["direct_permit"] is True

    def test_direct_permit_true_overrides_no_matching_rules(self) -> None:
        """direct_permit=True must grant ADMISSIBLE even when no rules match."""
        wrong_rule: dict[str, Any] = {"type": "action_allow", "action": "write"}
        alpha = _make_alpha(runtime_context={"direct_permit": True})
        gamma = _make_gamma(policies=[_policy_with_pre_rules([wrong_rule])])

        outcome = _permit_exists(alpha, gamma)

        assert outcome.value is True

    def test_direct_permit_false_default_does_not_grant(self) -> None:
        """direct_permit=False (the default) must not grant ADMISSIBLE alone."""
        alpha = _make_alpha(runtime_context={"direct_permit": False})
        wrong_rule: dict[str, Any] = {"type": "action_allow", "action": "write"}
        gamma = _make_gamma(policies=[_policy_with_pre_rules([wrong_rule])])

        outcome = _permit_exists(alpha, gamma)

        assert outcome.value is False

    def test_direct_permit_false_witness_is_false(self) -> None:
        """Witness direct_permit must be False when context uses the default."""
        alpha = _make_alpha()  # no direct_permit key in context
        gamma = _make_gamma()

        outcome = _permit_exists(alpha, gamma)

        assert outcome.witness["direct_permit"] is False

    def test_direct_permit_true_with_policies_present_unconfigured_false(self) -> None:
        """direct_permit=True with policies present must set unconfigured_fallback=False."""
        rule: dict[str, Any] = {"type": "action_allow", "action": "write"}
        alpha = _make_alpha(runtime_context={"direct_permit": True})
        gamma = _make_gamma(policies=[_policy_with_pre_rules([rule])])

        outcome = _permit_exists(alpha, gamma)

        assert outcome.value is True
        assert outcome.witness["unconfigured_fallback"] is False
