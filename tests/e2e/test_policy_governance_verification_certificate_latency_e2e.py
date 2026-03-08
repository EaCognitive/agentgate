"""E2E certificate-generation and latency checks for policy_governance_verification."""

from __future__ import annotations

import os
from statistics import mean
from time import perf_counter
from uuid import uuid4

import httpx
import pytest

pytestmark = pytest.mark.e2e


def _percentile(values: list[float], percentile: float) -> float:
    """Return percentile value using nearest-rank interpolation."""
    if not values:
        return 0.0

    ordered = sorted(values)
    index = int(round((len(ordered) - 1) * percentile))
    return ordered[index]


def _build_latency_payload(index: int) -> tuple[str, dict[str, object]]:
    """Return deterministic evaluation payload and chain identifier for one sample."""
    chain_id = f"pgk-cert-latency-{uuid4().hex[:8]}-{index}"
    return chain_id, {
        "principal": f"agent:e2e:latency:{index}",
        "action": "config:read",
        "resource": "tenant:default:config",
        "runtime_context": {"request_id": f"req-{index}"},
        "tenant_id": "default",
        "chain_id": chain_id,
    }


async def _run_latency_sample(
    e2e_client: httpx.AsyncClient,
    *,
    headers: dict[str, str],
    index: int,
) -> tuple[float, float, float]:
    """Execute one end-to-end certificate issuance and verification sample."""
    chain_id, payload = _build_latency_payload(index)
    request_start = perf_counter()
    evaluate_response = await e2e_client.post(
        "/api/security/admissibility/evaluate",
        json=payload,
        headers=headers,
    )
    evaluate_done = perf_counter()
    assert evaluate_response.status_code in {200, 403}, evaluate_response.text
    evaluate_body = evaluate_response.json()
    certificate = (
        evaluate_body["certificate"]
        if evaluate_response.status_code == 200
        else evaluate_body["detail"]["certificate"]
    )
    decision_id = certificate["decision_id"]
    assert decision_id
    assert certificate["signature"]
    runtime_solver = certificate["proof_payload"]["runtime_solver"]
    assert runtime_solver["solver_mode"] == "enforce"
    assert runtime_solver["solver_backend"] == "z3"

    verify_start = perf_counter()
    verify_response = await e2e_client.post(
        "/api/security/certificate/verify",
        json={"decision_id": decision_id},
        headers=headers,
    )
    verify_done = perf_counter()
    assert verify_response.status_code == 200, verify_response.text
    assert verify_response.json()["valid"] is True

    evidence_response = await e2e_client.get(
        f"/api/security/evidence/chain/{chain_id}",
        headers=headers,
    )
    assert evidence_response.status_code == 200, evidence_response.text
    assert evidence_response.json()["valid"] is True
    return (
        (evaluate_done - request_start) * 1000.0,
        (verify_done - verify_start) * 1000.0,
        (verify_done - request_start) * 1000.0,
    )


@pytest.mark.asyncio
async def test_policy_governance_verification_generates_real_certificates_with_latency_window(
    e2e_client: httpx.AsyncClient,
    registered_admin: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Run bounded E2E certificate generation and report end-to-end verification latency."""
    monkeypatch.setenv("AGENTGATE_Z3_MODE", "enforce")

    samples = max(1, int(os.getenv("PGK_CERT_E2E_SAMPLES", "8")))
    p95_budget_ms = float(os.getenv("PGK_CERT_E2E_P95_BUDGET_MS", "5000"))
    headers = registered_admin["headers"]

    evaluate_ms: list[float] = []
    verify_ms: list[float] = []
    end_to_end_ms: list[float] = []

    for index in range(samples):
        evaluate_latency, verify_latency, end_to_end_latency = await _run_latency_sample(
            e2e_client,
            headers=headers,
            index=index,
        )
        evaluate_ms.append(evaluate_latency)
        verify_ms.append(verify_latency)
        end_to_end_ms.append(end_to_end_latency)

    latency_metrics = {
        "samples": samples,
        "evaluate_avg_ms": round(mean(evaluate_ms), 2),
        "evaluate_p95_ms": round(_percentile(evaluate_ms, 0.95), 2),
        "verify_avg_ms": round(mean(verify_ms), 2),
        "verify_p95_ms": round(_percentile(verify_ms, 0.95), 2),
        "end_to_end_avg_ms": round(mean(end_to_end_ms), 2),
        "end_to_end_p95_ms": round(_percentile(end_to_end_ms, 0.95), 2),
    }
    print("PGK_CERT_E2E_LATENCY_METRICS", latency_metrics)

    assert latency_metrics["end_to_end_p95_ms"] <= p95_budget_ms, (
        "Policy governance certificate latency exceeded configured budget. "
        f"budget_ms={p95_budget_ms}, metrics={latency_metrics}"
    )
