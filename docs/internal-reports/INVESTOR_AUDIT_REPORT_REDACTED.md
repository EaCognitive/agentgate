# Redacted Audit Report (Investor Share Version)

Document classification: External Share / IP-Redacted
Generated (UTC): 2026-02-16T00:10:00Z
Assessment period: single completed formal verification run

## 1. Redaction Policy

This report is designed for external AI-assisted review while protecting proprietary implementation
intellectual property.

Redactions applied:

- no internal source file paths
- no implementation function/class names
- no private architecture module boundaries
- no internal prompt/policy authoring logic

Included for audit utility:

- run-level configuration and outcomes
- integrity hashes for run artifacts
- control-objective evidence statements
- explicit limitations and residual risk notes

## 2. Verification Run Snapshot

Run reference (public identifier): `RUN-2026-02-15-215135Z`

Measured outcomes:

- total transitions simulated: `500,000`
- formal evaluations with attached proof: `390,832`
- retained proof-ledger entries: `48,000`
- invariant violations detected: `0`
- final status: `PASS -- ZERO VIOLATIONS`

Runtime enforcement posture observed:

- enforcement mode: `enforce` for all recorded solver evaluations
- solver backend: `z3` for all recorded solver evaluations
- runtime solver failures: `0`
- solver drift events: `0`

## 3. Adversarial Coverage Summary

The run retained evidence across 13 adversarial operation classes, including:

- authentication misuse patterns
- principal impersonation attempts
- scope-escape attempts
- replay and stale-context attempts
- explicit deny/guard blocking attempts
- forgery-style tamper attempts
- obligation-bypass attempts

Retained decision outcomes:

- inadmissible decisions: `36,597`
- admissible decisions: `11,403`

Interpretation:

- the control surface was actively stressed with adversarial traffic,
  and the run produced no recorded invariant violation.

## 4. Control Objective Evidence (Redacted)

| Objective class | Evidence observed in run | Status |
| --- | --- | --- |
| Access control gating | High-volume inadmissible outcomes under adversarial traffic | Pass |
| Deny/guard precedence behavior | Dedicated deny/block classes present in retained evidence | Pass |
| Runtime enforcement integrity | 100% enforce-mode, z3-backed recorded evaluations | Pass |
| Solver stability | No solver failure or drift counters triggered | Pass |
| Audit integrity | Immutable artifact hashes recorded (Section 5) | Pass |

## 5. Artifact Integrity (External Manifest)

The following run artifacts are hash-anchored for independent integrity checks.

| Artifact Alias | SHA-256 | Size (bytes) |
| --- | --- | ---: |
| `A1_RESULTS_JSON` | `72b7cfe9c8dec3b99cba10cdb88e2c4a7968be737ddbe3a1e8b183dece2c9623` | 1,191 |
| `A2_LEDGER_JSONL` | `3b518a54c33d8f0d27677ed58d1ea9e997fe1db3cfe3d7221a0f2049fc1166d9` | 21,872,170 |
| `A3_SUMMARY_TEXT` | `56b90b82190e5a12b71e4a6c0a6f28e26162f3cbf5d70f35ec2bedf8c4a9ca63` | 802 |

## 6. Residual Risk Notes

1. Build provenance field was not populated in this run output (`build_sha=unknown`).
2. Proof ledger retention is sampled/capped evidence; full evaluation volume is reflected in run
   counters, not full-row persistence.
3. This redacted report is intended for assurance communication, not for reproducing proprietary
   implementation details.

## 7. AI-Use Guidance for Investors

Recommended prompts for AI review of this document:

1. "Summarize what formal assurances this run provides and what it does not prove."
2. "Explain the meaning of enforce-mode and zero-drift outcomes in non-technical terms."
3. "List follow-up diligence questions based on the residual risk notes."
4. "Assess whether the evidence package is sufficient for an initial technical-risk screening."

