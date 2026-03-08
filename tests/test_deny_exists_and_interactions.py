"""Tests for _deny_exists role_deny behavior and permit/deny predicate interactions.

Covers:
- role_deny rule producing DenyExists=True for matching caller roles
- role_deny non-matching and empty-role cases
- action_deny and environment.blocked_operations triggering DenyExists
- Witness structure integrity for _permit_exists across all scenarios
- Combined permit + deny predicate interaction for theorem admissibility logic

These tests operate directly on the solver predicate functions and require no
database or async context. They are a continuation of the matrix begun in
``tests/test_permit_exists_fallback.py``.
"""

# ---------------------------------------------------------------------------
# Standard Library
# ---------------------------------------------------------------------------
from typing import Any

# ---------------------------------------------------------------------------
# Third Party
# ---------------------------------------------------------------------------
import pytest

from server.policy_governance.kernel.formal_models import (
    AlphaContext,
    GammaKnowledgeBase,
)

# ---------------------------------------------------------------------------
# Local / Application
# ---------------------------------------------------------------------------
from server.policy_governance.kernel.solver_engine import (
    _deny_exists,
    _permit_exists,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PRINCIPAL = "agent:test-agent"
ACTION = "read"
RESOURCE = "data/reports"
TENANT = "tenant-alpha"

_ALLOW_ACTION_RULE: dict[str, Any] = {"type": "action_allow", "action": "read"}
_DENY_ACTION_RULE: dict[str, Any] = {"type": "action_deny", "action": "read"}
_ROLE_DENY_RULE: dict[str, Any] = {"type": "role_deny", "role": "auditor"}

_GRANT_READ_REPORTS: dict[str, Any] = {
    "grant_id": "grant-001",
    "allowed_actions": ["read"],
    "resource_scope": "data/reports",
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
# Tests: _deny_exists with role_deny rule
# ---------------------------------------------------------------------------
class TestDenyExistsRoleDeny:
    """Verify that a matching role_deny rule produces a DenyExists=True outcome."""

    def test_role_deny_matching_role_is_inadmissible(self) -> None:
        """Role_deny rule matching caller role must produce DenyExists=True."""
        alpha = _make_alpha(runtime_context={"role": "auditor"})
        gamma = _make_gamma(policies=[_policy_with_pre_rules([_ROLE_DENY_RULE])])

        outcome = _deny_exists(alpha, gamma)

        assert outcome.value is True

    def test_role_deny_matched_rule_in_witness(self) -> None:
        """The matched_rule in witness must reflect the role_deny rule."""
        alpha = _make_alpha(runtime_context={"role": "auditor"})
        gamma = _make_gamma(policies=[_policy_with_pre_rules([_ROLE_DENY_RULE])])

        outcome = _deny_exists(alpha, gamma)

        matched = outcome.witness["matched_rule"]
        assert matched is not None
        assert matched["type"] == "role_deny"

    def test_role_deny_non_matching_role_is_no_deny(self) -> None:
        """Role_deny rule must not affect callers with a different role."""
        alpha = _make_alpha(runtime_context={"role": "developer"})
        gamma = _make_gamma(policies=[_policy_with_pre_rules([_ROLE_DENY_RULE])])

        outcome = _deny_exists(alpha, gamma)

        assert outcome.value is False

    def test_role_deny_empty_role_context_does_not_match(self) -> None:
        """Role_deny rule must not match when caller has no role in context."""
        alpha = _make_alpha(runtime_context={})
        gamma = _make_gamma(policies=[_policy_with_pre_rules([_ROLE_DENY_RULE])])

        outcome = _deny_exists(alpha, gamma)

        assert outcome.value is False

    def test_deny_exists_predicate_name(self) -> None:
        """Predicate name on DenyExists outcome must always be 'DenyExists'."""
        alpha = _make_alpha()
        gamma = _make_gamma()

        outcome = _deny_exists(alpha, gamma)

        assert outcome.name == "DenyExists"

    def test_deny_exists_false_with_no_policies(self) -> None:
        """DenyExists must be False when no policies are configured."""
        alpha = _make_alpha()
        gamma = _make_gamma()

        outcome = _deny_exists(alpha, gamma)

        assert outcome.value is False

    def test_deny_exists_post_rule_role_deny(self) -> None:
        """Role_deny in post_rules must also raise DenyExists."""
        alpha = _make_alpha(runtime_context={"role": "auditor"})
        gamma = _make_gamma(policies=[_policy_with_post_rules([_ROLE_DENY_RULE])])

        outcome = _deny_exists(alpha, gamma)

        assert outcome.value is True

    def test_deny_exists_action_deny_matching_action(self) -> None:
        """Action_deny matching the caller's action must raise DenyExists."""
        alpha = _make_alpha()  # action=read
        gamma = _make_gamma(policies=[_policy_with_pre_rules([_DENY_ACTION_RULE])])

        outcome = _deny_exists(alpha, gamma)

        assert outcome.value is True

    def test_deny_exists_blocked_operations_env_raises_deny(self) -> None:
        """Blocked action in environment.blocked_operations must raise DenyExists."""
        alpha = _make_alpha()  # action=read
        gamma = _make_gamma(environment={"blocked_operations": ["read"]})

        outcome = _deny_exists(alpha, gamma)

        assert outcome.value is True

    def test_deny_exists_blocked_operations_non_matching_does_not_raise(self) -> None:
        """Blocked operation for a different action must not trigger DenyExists."""
        alpha = _make_alpha()  # action=read
        gamma = _make_gamma(environment={"blocked_operations": ["delete"]})

        outcome = _deny_exists(alpha, gamma)

        assert outcome.value is False

    def test_deny_exists_witness_has_evaluated_rules_key(self) -> None:
        """DenyExists witness must always contain 'evaluated_rules' list."""
        alpha = _make_alpha(runtime_context={"role": "auditor"})
        gamma = _make_gamma(policies=[_policy_with_pre_rules([_ROLE_DENY_RULE])])

        outcome = _deny_exists(alpha, gamma)

        assert "evaluated_rules" in outcome.witness
        assert isinstance(outcome.witness["evaluated_rules"], list)

    def test_deny_exists_witness_matched_rule_is_none_when_no_deny(self) -> None:
        """Witness matched_rule must be None when DenyExists=False."""
        alpha = _make_alpha()
        gamma = _make_gamma()

        outcome = _deny_exists(alpha, gamma)

        assert outcome.witness["matched_rule"] is None


# ---------------------------------------------------------------------------
# Tests: combined witness structure integrity
# ---------------------------------------------------------------------------
class TestPermitExistsWitnessIntegrity:
    """Verify that the witness dict always contains the required keys."""

    @pytest.mark.parametrize(
        "policies,active_grants",
        [
            pytest.param([], [], id="bare_unconfigured"),
            pytest.param(
                [_policy_with_pre_rules([_ALLOW_ACTION_RULE])],
                [],
                id="with_allow_rule",
            ),
            pytest.param(
                [_policy_with_pre_rules([_DENY_ACTION_RULE])],
                [],
                id="with_deny_only",
            ),
            pytest.param([], [_GRANT_READ_REPORTS], id="with_grant"),
        ],
    )
    def test_witness_always_has_required_keys(
        self,
        policies: list[dict[str, Any]],
        active_grants: list[dict[str, Any]],
    ) -> None:
        """Witness dict must always contain all four required keys."""
        alpha = _make_alpha()
        gamma = _make_gamma(policies=policies, active_grants=active_grants)

        outcome = _permit_exists(alpha, gamma)

        required_keys = {
            "policy_matches",
            "grant_matches",
            "direct_permit",
            "unconfigured_fallback",
        }
        assert required_keys.issubset(outcome.witness.keys())

    def test_witness_policy_matches_is_list(self) -> None:
        """policy_matches in witness must always be a list type."""
        alpha = _make_alpha()
        gamma = _make_gamma()

        outcome = _permit_exists(alpha, gamma)

        assert isinstance(outcome.witness["policy_matches"], list)

    def test_witness_grant_matches_is_list(self) -> None:
        """grant_matches in witness must always be a list type."""
        alpha = _make_alpha()
        gamma = _make_gamma()

        outcome = _permit_exists(alpha, gamma)

        assert isinstance(outcome.witness["grant_matches"], list)

    def test_witness_direct_permit_is_bool(self) -> None:
        """direct_permit in witness must always be a bool type."""
        alpha = _make_alpha()
        gamma = _make_gamma()

        outcome = _permit_exists(alpha, gamma)

        assert isinstance(outcome.witness["direct_permit"], bool)

    def test_witness_unconfigured_fallback_is_bool(self) -> None:
        """unconfigured_fallback in witness must always be a bool type."""
        alpha = _make_alpha()
        gamma = _make_gamma()

        outcome = _permit_exists(alpha, gamma)

        assert isinstance(outcome.witness["unconfigured_fallback"], bool)


# ---------------------------------------------------------------------------
# Tests: combined permit + deny interaction
# ---------------------------------------------------------------------------
class TestPermitAndDenyInteraction:
    """Verify that permit and deny predicates interact correctly.

    These tests do not call evaluate_admissibility (which requires a DB session);
    they verify that the individual predicate functions produce consistent values
    that, when combined with the theorem, yield the expected admissibility.
    """

    def test_allow_rule_present_and_deny_absent_yields_admissible(self) -> None:
        """Allow match + no deny match must satisfy the permit-and-not-deny condition."""
        alpha = _make_alpha()
        gamma = _make_gamma(policies=[_policy_with_pre_rules([_ALLOW_ACTION_RULE])])

        permit = _permit_exists(alpha, gamma)
        deny = _deny_exists(alpha, gamma)

        assert permit.value is True
        assert deny.value is False

    def test_allow_rule_and_role_deny_together(self) -> None:
        """Allow rule + matching role_deny must yield permit=True but deny=True.

        The full theorem would be INADMISSIBLE due to DenyExists=True overriding
        the permit.
        """
        rules = [_ALLOW_ACTION_RULE, _ROLE_DENY_RULE]
        alpha = _make_alpha(runtime_context={"role": "auditor"})
        gamma = _make_gamma(policies=[_policy_with_pre_rules(rules)])

        permit = _permit_exists(alpha, gamma)
        deny = _deny_exists(alpha, gamma)

        assert permit.value is True
        assert deny.value is True

    def test_no_allow_rule_and_deny_rule(self) -> None:
        """No allow match + deny match must yield permit=False and deny=True."""
        alpha = _make_alpha()  # action=read
        gamma = _make_gamma(policies=[_policy_with_pre_rules([_DENY_ACTION_RULE])])

        permit = _permit_exists(alpha, gamma)
        deny = _deny_exists(alpha, gamma)

        assert permit.value is False
        assert deny.value is True

    def test_unconfigured_system_deny_is_false(self) -> None:
        """Bare unconfigured system must have deny=False, affirming fail-open."""
        alpha = _make_alpha()
        gamma = _make_gamma()

        permit = _permit_exists(alpha, gamma)
        deny = _deny_exists(alpha, gamma)

        assert permit.value is True
        assert deny.value is False

    def test_grant_match_and_no_deny_satisfies_theorem_permit_conditions(self) -> None:
        """Grant match without a deny rule must yield permit=True, deny=False."""
        alpha = _make_alpha()
        gamma = _make_gamma(active_grants=[_GRANT_READ_REPORTS])

        permit = _permit_exists(alpha, gamma)
        deny = _deny_exists(alpha, gamma)

        assert permit.value is True
        assert deny.value is False

    def test_grant_match_with_env_block_yields_permit_true_deny_true(self) -> None:
        """Grant match + environment block must yield permit=True but deny=True.

        This combination represents a conflict: the grant allows the action but
        a guardrail-level block overrides it, rendering the theorem INADMISSIBLE.
        """
        alpha = _make_alpha()  # action=read
        gamma = _make_gamma(
            active_grants=[_GRANT_READ_REPORTS],
            environment={"blocked_operations": ["read"]},
        )

        permit = _permit_exists(alpha, gamma)
        deny = _deny_exists(alpha, gamma)

        assert permit.value is True
        assert deny.value is True
