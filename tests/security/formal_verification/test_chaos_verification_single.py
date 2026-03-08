"""Single-threaded formal verification chaos tests."""

from __future__ import annotations

import pytest

from ea_agentgate.verification import verify_plan
from tests.security.formal_verification.support import (
    deny_delete_prod_policy,
    permit_policy,
)

pytestmark = [pytest.mark.formal_heavy]


def _build_steps(total: int, blocked_index: int) -> list[dict[str, str]]:
    """Build deterministic plan steps with a single blocked operation."""
    steps = [{"action": "read", "resource": f"/prod/object/{index}"} for index in range(total)]
    steps[blocked_index] = {
        "action": "delete",
        "resource": f"/prod/object/{blocked_index}",
    }
    return steps


def test_formal_plan_verification_is_deterministic_under_load() -> None:
    """Repeated heavy plan verification should remain deterministic."""
    total_steps = 800
    blocked_index = 577
    steps = _build_steps(total=total_steps, blocked_index=blocked_index)
    policies = [permit_policy(), deny_delete_prod_policy()]

    blocked_indices: list[int] = []
    for _ in range(24):
        result = verify_plan(
            principal="agent:formal-heavy",
            steps=steps,
            policies=policies,
            tenant_id="acme-heavy",
        )
        assert result.safe is False
        blocked_indices.append(result.blocked_step_index)
        assert result.total_steps == total_steps
        assert len(result.step_results) == blocked_index + 1

    assert blocked_indices == [blocked_index] * 24
