# ADR 0004: Concatenated, both-must-verify signature combiner

**Status:** Accepted

## Context

A hybrid signature combines two component signatures over the same message.
We need a wire format and a verification rule such that the construction is
secure (existentially unforgeable) when **either** component scheme is
secure.

## Options considered

### A. Concatenate signatures; both must verify (our choice)

```
sig = algId || sig_classical || sig_pq
verify(pk, m, sig) = verify_classical(pk_c, m, sig_classical) AND
                    verify_pq(pk_pq, m, sig_pq)
```

Each component scheme signs the message bytes directly. Both schemes do
their own internal hashing (Ed25519 prehashes with SHA-512 plus its domain
separator; ML-DSA uses its FIPS-204 message-binding construction). No
extra hash by us.

### B. Sign a transcript hash that includes both public keys

```
to_sign = SHA-256("PQH-HYBSIG" || pk_classical || pk_pq || message)
sig = algId || sign_classical(to_sign) || sign_pq(to_sign)
```

Adds a layer of cross-binding. Mostly redundant — each signature already
includes its own algorithm's domain separator, and the verifier already
holds *the* public key it's verifying against.

### C. Combiner that ANDs the verify results but allows one-of-two signing

```
sig = sig_classical XOR sig_pq  (or similar trickery)
```

Saves bytes but loses the "either-secure" property; if `sig_pq` is broken
the attacker can recover `sig_classical` from `sig_pq XOR sig_combined`.
Rejected — fancier is worse.

## Decision

Option **A: concatenated signatures, both must verify**.

```
HybridSignature(3374 bytes) := algId(1) || Ed25519_sig(64) || MLDSA65_sig(3309)
```

## Rationale

- **Provably unforgeable when either scheme is.** This is the textbook
  combiner; forging the hybrid requires forging both components.
- **Simplest possible construction.** No extra hash, no extra domain
  separator, nothing to argue about in a security proof.
- **No cross-binding pitfalls.** Each scheme's internal domain separator
  is sufficient; we don't introduce a new one that future cryptanalysis
  would have to study independently.
- **Algorithm-id byte at the front** disambiguates the combination so a
  future `Ed448MlDsa87` (say) doesn't get confused with v1.

## Consequences

- A hybrid signature is the sum of its parts (3374 = 1 + 64 + 3309 bytes).
- Verification cost is the sum of both component verifications. Ed25519
  is ~1 ms; ML-DSA-65 is ~0.5 ms; hybrid verify is dominated by the
  Ed25519 hash + scalar operations.
- ML-DSA-65 signing is randomized by default, so two hybrid signatures
  over the same message under the same key will differ in the ML-DSA
  half. This is documented and tested.
- Both component signatures use **empty context** per FIPS 204 / RFC 8032,
  matching the .NET native default. If we add a context-binding variant
  later, it gets a new algorithm-id.
