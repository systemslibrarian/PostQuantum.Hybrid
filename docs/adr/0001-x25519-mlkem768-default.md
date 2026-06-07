# ADR 0001: X25519 + ML-KEM-768 as the default hybrid KEM

**Status:** Accepted

## Context

We need one default hybrid KEM combination for v1 that we are willing to
recommend without qualification for the majority of .NET applications.

The hybrid construction must combine a well-understood classical KEM with a
NIST-standardized post-quantum KEM. The choices on the table:

- Classical: X25519, X448, P-256, P-384.
- Post-quantum: ML-KEM-512 (Level 1), ML-KEM-768 (Level 3), ML-KEM-1024 (Level 5).

## Decision

The single supported combination in v1 is **X25519 + ML-KEM-768**.

## Rationale

### Why X25519 over P-256/P-384/X448

- **Speed:** X25519 is fast on every platform .NET supports, with no curve
  validation overhead and no malleable points.
- **Implementation maturity:** BouncyCastle has a well-audited X25519
  implementation; native .NET will likely expose X25519 in a future release.
- **Industry alignment:** The IETF TLS WG selected X25519 as the classical
  half of the standard hybrid group `X25519MLKEM768`.

### Why ML-KEM-768 over -512 or -1024

- **Level 3 (~AES-192) is the conservative default.** Level 1 (-512) is the
  minimum NIST-acceptable level and trades security margin for size. Level
  5 (-1024) doubles the artifact sizes without addressing any threat
  classically reachable in our lifetimes.
- **Matches the IETF default.** TLS 1.3 hybrid key share `X25519MLKEM768`
  uses exactly this combination. Codebases moving toward PQ TLS will see
  this combination in their network traces; PostQuantum.Hybrid produces
  blobs callers can reason about in the same terms.
- **Matches matched security:** X25519's ~128-bit classical security
  pairs reasonably with ML-KEM-768's Level 3. Mixing X25519 with -1024
  would be an asymmetric pairing that adds size without adding meaningful
  defense.

## Consequences

- v1 has exactly one KEM combination; callers cannot misconfigure.
- Migration to a different combination later requires only a new
  algorithm-id byte; v1 keys and ciphertexts remain parseable indefinitely.
- Total v1 KEM artifact sizes: 1217 B public key, 2433 B private key, 1121 B
  ciphertext, 32 B shared secret.
