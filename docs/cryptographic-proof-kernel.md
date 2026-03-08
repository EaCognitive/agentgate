# Cryptographic Proof Requirements and Deterministic Kernel Security

**Version:** 1.0
**Last Updated:** 2025-02-11
**Scope:** AgentGate Security Kernel -- Formal Verification Architecture

---

## 1. Overview

The AgentGate Security Kernel implements a proof-carrying authorization
framework where every access decision produces a cryptographically signed
certificate that can be independently verified offline. The kernel is
designed around three foundational guarantees:

1. **Determinism**: Given identical inputs (AlphaContext, GammaKnowledgeBase),
   the solver always produces the same DecisionResult and proof payload.
2. **Cryptographic Non-Repudiation**: Every certificate is signed with
   Ed25519, binding the decision to the exact alpha and gamma state hashes.
3. **Tamper-Evident Audit**: The evidence chain uses hash-linked entries
   (Merkle chain) so any post-hoc modification is detectable.

---

## 2. Canonical Serialization

All hashing in the kernel operates on **canonical JSON** -- a deterministic
serialization format that eliminates ambiguity:

```python
# server/policy_governance/kernel/formal_models.py:40-48
def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,          # Key ordering is deterministic
        separators=(",", ":"),   # No whitespace
        ensure_ascii=True,       # No Unicode escaping variance
        default=str,             # datetime/uuid -> string
    )
```

**Why this matters**: Two systems evaluating the same logical state will
produce byte-identical JSON, which means their SHA-256 hashes will match
exactly. Without canonical serialization, key ordering differences or
whitespace would produce different hashes for semantically identical data.

---

## 3. The Theorem

The admissibility decision is a conjunction of six predicates:

```
Admissible(alpha, Gamma) :=
    AuthValid(alpha, Gamma)
    AND LineageValid(alpha, Gamma)
    AND PermitExists(alpha, Gamma)
    AND NOT DenyExists(alpha, Gamma)
    AND ObligationsMet(alpha, Gamma)
    AND ContextBound(alpha, Gamma)
```

Each predicate is evaluated independently and produces a **witness** -- a
JSON object that records the exact evidence used to reach its boolean value.
The witnesses collectively form the **constructive proof** or
**counterexample** attached to the certificate.

### 3.1 Predicate Definitions

| Predicate | True When | Witness Contains |
|---|---|---|
| AuthValid | Principal is authenticated AND gamma.principal matches alpha.principal | `authenticated`, `gamma_principal`, `alpha_principal` |
| LineageValid | Delegation chain from root to principal is unbroken, unrevoked, within depth limit, and respects attenuation | `reason`, `chain` (grant IDs), `details` |
| PermitExists | At least one policy rule or delegation grant authorizes the action on the resource | `policy_matches`, `grant_matches`, `direct_permit` |
| NOT DenyExists | No deny rule or blocked operation matches the action | `matched_rule`, `evaluated_rules`, `deny_absence_proof` |
| ObligationsMet | All applicable obligations (MFA, approval, preview-confirm) are satisfied | `failures`, `checked_count` |
| ContextBound | SHA-256 of runtime_context matches alpha.context_hash | `expected_hash`, `provided_hash`, `gamma_hash` |

### 3.2 ContextBound -- Binding State to Decision

The ContextBound predicate prevents replay attacks where an attacker
resubmits a valid certificate with modified runtime flags:

```python
# solver_engine.py:247-258
def _context_bound(alpha, gamma):
    expected_hash = sha256_hex(canonical_json(alpha.runtime_context))
    value = alpha.context_hash == expected_hash
```

The `context_hash` is computed at `AlphaContext.from_runtime()` construction
time and baked into the alpha. Any modification to runtime_context after
construction invalidates the context_hash, causing ContextBound to fail.

---

## 4. Cryptographic Signing with Ed25519

### 4.1 Key Derivation

The signing key is derived deterministically from a secret:

```python
# formal_models.py:91-109
def _derive_private_key_seed() -> bytes:
    encoded_seed = os.getenv("AGENTGATE_DECISION_SIGNING_KEY", "")
    if encoded_seed:
        candidate = base64.b64decode(encoded_seed)
        if len(candidate) == 32:
            return candidate
    # Fallback: SHA-256 of SECRET_KEY
    fallback = os.getenv("SECRET_KEY", "agentgate-development-signing-key")
    return hashlib.sha256(fallback.encode("utf-8")).digest()

def load_private_key() -> Ed25519PrivateKey:
    seed = _derive_private_key_seed()
    return Ed25519PrivateKey.from_private_bytes(seed)
```

**Ed25519** is a 256-bit elliptic curve signature scheme. It provides:
- 128-bit security level
- Deterministic signatures (same input always produces the same signature)
- Small signatures (64 bytes)
- Fast verification (~70 microseconds on modern hardware)

### 4.2 Certificate Signing

```python
# formal_models.py:266-270
def sign(self, private_key: Ed25519PrivateKey) -> DecisionCertificate:
    signed = private_key.sign(self.unsigned_payload())
    self.signature = base64.urlsafe_b64encode(signed).decode("ascii")
    return self
```

The `unsigned_payload()` method serializes the entire certificate (with
`signature=None`) into canonical JSON bytes. This is the exact byte
sequence that gets signed. Any modification to the certificate fields
after signing will cause verification to fail.

### 4.3 Verification

```python
# formal_models.py:272-281
def verify(self, public_key: Ed25519PublicKey) -> bool:
    if not self.signature:
        return False
    signature_bytes = base64.urlsafe_b64decode(self.signature)
    public_key.verify(signature_bytes, self.unsigned_payload())
    return True
```

Verification is a pure function: given the public key and the certificate,
anyone can confirm the decision was made by the holder of the private key.

---

## 5. Hash-Linked Evidence Chain (Merkle Chain)

### 5.1 Chain Structure

Each decision appends an immutable entry to the evidence chain:

```
Entry[0]:  payload_hash_0 = SHA-256(canonical_json(payload_0))
           current_hash_0 = SHA-256(payload_hash_0 + ":")

Entry[1]:  payload_hash_1 = SHA-256(canonical_json(payload_1))
           current_hash_1 = SHA-256(payload_hash_1 + ":" + current_hash_0)

Entry[N]:  payload_hash_N = SHA-256(canonical_json(payload_N))
           current_hash_N = SHA-256(payload_hash_N + ":" + current_hash_{N-1})
```

### 5.2 Tamper Detection

Verification walks the chain from entry 0 and recomputes every hash:

```python
# evidence_log.py:137-167
for row in rows:
    expected_payload_hash = sha256_hex(canonical_json(row.payload_json))
    if expected_payload_hash != row.payload_hash:
        # Payload was modified after persistence
        return EvidenceChainStatus(valid=False, ...)

    expected_hash = sha256_hex(f"{row.payload_hash}:{previous_hash or ''}")
    if expected_hash != row.current_hash:
        # Chain link was broken
        return EvidenceChainStatus(valid=False, ...)

    if row.previous_hash != previous_hash:
        # Previous-hash pointer was tampered
        return EvidenceChainStatus(valid=False, ...)
```

Three independent integrity checks per entry:
1. **Payload integrity**: Recompute hash of payload JSON.
2. **Chain integrity**: Recompute current_hash from payload_hash + previous_hash.
3. **Linkage integrity**: Verify stored previous_hash matches prior entry.

If any check fails, the exact `hop_index` where corruption occurred is
reported.

---

## 6. Deterministic Kernel Security Measures

### 6.1 Canonical Hashing of All State

Every data structure in the kernel has a deterministic hash:

| Structure | Hash Field | Computed From |
|---|---|---|
| AlphaContext | `alpha_hash` | SHA-256 of canonical JSON of all alpha fields |
| AlphaContext | `context_hash` | SHA-256 of canonical JSON of runtime_context alone |
| GammaKnowledgeBase | `gamma_hash` | SHA-256 of canonical JSON of all gamma fields (with gamma_hash=None) |
| DecisionCertificate | `certificate_hash` | SHA-256 of unsigned_payload() bytes |
| DecisionCertificate | `theorem_hash` | SHA-256 of theorem expression text |
| EvidenceChain entry | `payload_hash` | SHA-256 of canonical JSON of {alpha, gamma_hash, certificate} |
| EvidenceChain entry | `current_hash` | SHA-256 of `payload_hash:previous_hash` |

### 6.2 Attenuation Invariant (Delegation)

Delegation grants enforce monotonic privilege reduction:

```
child_actions SUBSET_OF parent_actions
child_scope  SUBSET_OF parent_scope
```

A child delegation can never grant more permissions than its parent.
This is verified both at issuance time (database write) and at evaluation
time (lineage validation in the solver).

### 6.3 Transitive Revocation

When a delegation grant is revoked, all descendant grants are recursively
revoked:

```
revoke(grant_A) -> revoke(grant_B where parent=A)
                -> revoke(grant_C where parent=B)
                -> ...
```

The solver then rejects any action that references a revoked grant
anywhere in its lineage chain.

### 6.4 UUIDv7 Time-Ordered Identifiers

All decision_ids use UUIDv7 (RFC 9562), which embeds a millisecond
timestamp in the first 48 bits. This provides:
- Globally unique identifiers without coordination
- Natural chronological ordering for audit queries
- Overflow protection (explicit check for timestamp >= 2^48)

### 6.5 Denial Proof Construction

When the solver denies a request, it produces one of two proof types:

- **COUNTEREXAMPLE**: A specific deny rule that matched. Contains the
  rule object and all evaluated rules.
- **UNSAT_CORE**: The list of predicates that evaluated to False when
  no explicit deny rule matched (e.g., PermitExists=False means no
  grant or policy authorized the action).

Both proof types are machine-parseable and attached to the signed
certificate.

---

## 7. Distributed Consensus and Transparency

### 7.1 Certificate Transparency Log

Every certificate is appended to an immutable transparency log with
sequential indices. Verification detects:
- Index gaps (missing entries)
- Invalid certificate hashes (wrong length or format)

### 7.2 N-of-M Co-Signing

When consensus is enabled, remote SafetyNodes independently re-evaluate
the admissibility theorem. If any node disagrees:
- A GlobalRevocationRecord is persisted
- All nodes are notified via HTTP POST
- The certificate is permanently revoked

### 7.3 Honey-Token Detection

Canary resources injected into the gamma knowledge base detect
compromised agents. The trap_hash is computed as:

```
trap_hash = SHA-256(token_id + ":" + salt)
```

The token_id cannot be derived from the trap_hash (pre-image resistance).
When triggered, graduated trust degradation applies:
- Severity 1 (RESOURCE): Log only
- Severity 2 (TOOL): Downgrade trust flags on all active grants
- Severity 3 (CREDENTIAL): Revoke all active delegation grants

---

## 8. Invariant Synthesis (Property-Based Fuzzing)

The spec_synthesizer generates randomized (alpha, gamma) pairs and
evaluates them through the solver. It detects three classes of policy gaps:

1. **INSTABILITY**: A single mutation to gamma flips the decision.
   This means the policy is fragile -- one rule change reverses enforcement.
2. **SURPRISING_ADMIT**: The solver admits despite deny rules existing.
   This may indicate the deny rules are not matching the action/resource.
3. **SURPRISING_DENY**: The solver denies despite no deny rules and
   permits existing. This may indicate an authentication or obligation
   failure.

Discovered invariants are expressed as DTSL (Decision Tree Specification
Language) rules and persisted for human review.

---

## 9. Chaos Verification Verification

The current verification sweep uses
`tests/security/test_verification_controls.py`,
`tests/test_policy_governance_verification_router.py`, and
`tests/e2e/test_policy_governance_verification_certificate_latency_e2e.py`
to stress-test kernel invariants and runtime behavior. The campaign:

- Simulates 100,000+ state transitions with seeded randomness
- Verifies the kernel matches the GhostState after every operation
- Tests clock skew, key rollover races, binary garbage inputs, and
  integer overflow conditions
- Maintains a flight recorder that dumps SHA-256 state vectors and
  saves reproduction artifacts for any failure

The campaign produces a machine-parseable report with transition counts,
invariant violation counts, and a pass/fail status.
