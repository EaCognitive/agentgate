"""Custom mutation-based formal verification chaos tests."""

from __future__ import annotations

import copy

import pytest

from ea_agentgate.verification import check_admissibility, verify_certificate

pytestmark = [pytest.mark.formal_heavy]


def _permit_policy() -> dict[str, object]:
    """Allow all actions to create a valid baseline certificate."""
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


def test_certificate_mutation_campaign_detects_tampering() -> None:
    """Repeated signature/hash mutations must be rejected."""
    baseline = check_admissibility(
        principal="agent:mutation",
        action="read",
        resource="/prod/records/1",
        policies=[_permit_policy()],
        tenant_id="mutation-heavy",
    )

    clean_verification = verify_certificate(baseline.certificate_raw)
    assert clean_verification.valid is True

    for iteration in range(300):
        tampered = copy.deepcopy(baseline.certificate_raw)
        mutation_kind = iteration % 3
        if mutation_kind == 0:
            original_hash = str(tampered.get("theorem_hash", ""))
            tampered["theorem_hash"] = f"{original_hash[:-1]}X"
        elif mutation_kind == 1:
            original_signature = str(tampered.get("signature", ""))
            tampered["signature"] = f"{original_signature[:-1]}A"
        else:
            proof_payload = dict(tampered.get("proof_payload") or {})
            proof_payload["chaos_iteration"] = iteration
            tampered["proof_payload"] = proof_payload

        verification = verify_certificate(tampered)
        assert verification.valid is False
