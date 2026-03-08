"""Parallel formal verification chaos tests."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from ea_agentgate.verification import check_admissibility
from tests.security.formal_verification.support import (
    deny_delete_prod_policy,
    permit_policy,
)

pytestmark = [pytest.mark.formal_heavy]


def _run_case(case_index: int) -> str:
    """Execute one formal verification case and return the decision label."""
    action = "delete" if case_index % 7 == 0 else "read"
    resource = f"/prod/resource/{case_index}"
    result = check_admissibility(
        principal=f"agent:parallel:{case_index % 5}",
        action=action,
        resource=resource,
        policies=[permit_policy(), deny_delete_prod_policy()],
        tenant_id="parallel-heavy",
        runtime_context={"request_index": case_index},
    )
    return result.decision


def test_parallel_formal_verification_is_stable() -> None:
    """Heavy parallel checks should complete without inconsistent outcomes."""
    indices = list(range(240))

    with ThreadPoolExecutor(max_workers=16) as pool:
        decisions_first = list(pool.map(_run_case, indices))

    with ThreadPoolExecutor(max_workers=16) as pool:
        decisions_second = list(pool.map(_run_case, indices))

    assert decisions_first == decisions_second
    assert "INADMISSIBLE" in decisions_first
    assert "ADMISSIBLE" in decisions_first
