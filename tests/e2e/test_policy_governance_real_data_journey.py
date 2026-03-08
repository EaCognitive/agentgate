"""E2E policy-governance verification against repository-managed scenario data."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

pytestmark = pytest.mark.e2e


SCENARIO_CORPUS_PATH = (
    Path(__file__).resolve().parent / "data" / "policy_governance_formal_scenarios.json"
)


def _load_scenarios() -> list[dict[str, object]]:
    """Load the scenario corpus from disk and validate its top-level shape."""
    raw = json.loads(SCENARIO_CORPUS_PATH.read_text(encoding="utf-8"))
    if not isinstance(raw, list) or not raw:
        raise AssertionError("Scenario corpus must be a non-empty JSON list")
    return raw


def _build_scenario_payload(
    scenario: dict[str, object],
    *,
    chain_id: str,
    principal: str,
) -> dict[str, object]:
    """Build a live evaluation request payload from a scenario corpus entry."""
    return {
        "principal": principal,
        "action": scenario["action"],
        "resource": scenario["resource"],
        "runtime_context": scenario["runtime_context"],
        "tenant_id": scenario.get("tenant_id", "default"),
        "chain_id": chain_id,
    }


async def _execute_scenario(
    e2e_client: httpx.AsyncClient,
    *,
    headers: dict[str, str],
    chain_id: str,
    payload: dict[str, object],
) -> None:
    """Run one scenario through evaluate, certificate verify, and evidence verify paths."""
    evaluate_response = await e2e_client.post(
        "/api/security/admissibility/evaluate",
        json=payload,
        headers=headers,
    )
    assert evaluate_response.status_code in {200, 403}, evaluate_response.text
    evaluate_body = evaluate_response.json()
    certificate = (
        evaluate_body["certificate"]
        if evaluate_response.status_code == 200
        else evaluate_body["detail"]["certificate"]
    )
    decision_id = certificate["decision_id"]
    runtime_solver = certificate["proof_payload"]["runtime_solver"]
    assert runtime_solver["solver_mode"] == "enforce"
    assert runtime_solver["solver_backend"] == "z3"

    verify_response = await e2e_client.post(
        "/api/security/certificate/verify",
        json={"decision_id": decision_id},
        headers=headers,
    )
    assert verify_response.status_code == 200, verify_response.text
    assert verify_response.json()["valid"] is True

    evidence_response = await e2e_client.get(
        f"/api/security/evidence/chain/{chain_id}",
        headers=headers,
    )
    assert evidence_response.status_code == 200, evidence_response.text
    evidence_body = evidence_response.json()
    assert evidence_body["valid"] is True
    assert evidence_body["checked_entries"] >= 1


@pytest.mark.asyncio
async def test_formal_verification_executes_real_e2e_scenario_corpus(
    e2e_client: httpx.AsyncClient,
    registered_admin: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Execute scenario corpus through live formal routes and verify evidence chain output."""
    monkeypatch.setenv("AGENTGATE_Z3_MODE", "enforce")

    scenarios = _load_scenarios()
    headers = registered_admin["headers"]
    run_id = uuid4().hex[:10]

    executed_count = 0
    for index, scenario in enumerate(scenarios):
        scenario_id = str(scenario.get("id", f"scenario-{index}"))
        chain_id = f"e2e-policy-data-{run_id}-{scenario_id}"
        principal = f"agent:e2e:scenario:{index}"
        payload = _build_scenario_payload(
            scenario,
            chain_id=chain_id,
            principal=principal,
        )
        await _execute_scenario(
            e2e_client,
            headers=headers,
            chain_id=chain_id,
            payload=payload,
        )
        executed_count += 1

    assert executed_count == len(scenarios)
