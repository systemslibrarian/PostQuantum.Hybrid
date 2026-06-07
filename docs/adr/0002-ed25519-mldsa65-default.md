# ADR 0002: Ed25519 + ML-DSA-65 as the default hybrid signature

**Status:** Accepted

## Context

We need one default hybrid signature combination for v1. The classical
options are Ed25519, Ed448, ECDSA on P-256/P-384, and RSA. The PQ options
are ML-DSA-44 (Level 2), ML-DSA-65 (Level 3), and ML-DSA-87 (Level 5).
SLH-DSA (SPHINCS+) is also a NIST-standardized stateless hash-based option.

## Decision

The single supported combination in v1 is **Ed25519 + ML-DSA-65**.

## Rationale

### Why Ed25519 over ECDSA / RSA / Ed448

- **Deterministic and fast.** Ed25519 signatures are deterministic and
  small (64 bytes), with simple verification.
- **Modern default.** Ed25519 is what SSH, age, signify, libsodium, and
  most new protocols default to.
- **Implementation maturity.** BouncyCastle and (soon) native .NET have
  well-audited Ed25519. ECDSA requires per-signature nonce generation that
  has historically been a source of catastrophic bugs.

### Why ML-DSA-65 over ML-DSA-44 / ML-DSA-87 / SLH-DSA

- **Level 3 = matched security level with Ed25519.** ML-DSA-44 is Level 2
  (~AES-128); ML-DSA-65 is Level 3 (~AES-192). Pairing Level 3 PQ with
  ~128-bit classical Ed25519 keeps the hybrid security floor at Level 3 in
  PQ-only scenarios while keeping artifact sizes manageable (3309-byte sig
  vs. ML-DSA-87's 4627 bytes).
- **NIST's general-purpose recommendation.** NIST explicitly calls out
  ML-DSA-65 as a sensible default for "most applications".
- **Industry alignment.** IETF Composite Signature drafts converge on
  Ed25519+ML-DSA-65 as one of the standard composite algorithm OIDs.
- **Why not SLH-DSA?** SLH-DSA signatures are 7,856 to 49,856 bytes
  (parameter-set dependent) and signing is two to three orders of
  magnitude slower than ML-DSA. Reserve SLH-DSA for use cases that
  specifically need hash-based security (e.g. firmware signing where
  long-term lattice assumptions are uncomfortable). For general
  application use, ML-DSA is the better trade.

## Consequences

- v1 hybrid signature size: 3374 bytes. Public key 1985 B, private key 4065 B.
- ML-DSA signing is **randomized by default** (we use the empty-context
  pure-ML-DSA mode); two signatures over the same message under the same
  key will differ. This is documented in `docs/SPEC.md` and asserted in tests.
- Migration to ML-DSA-87 / SLH-DSA happens via a new algorithm-id byte; no
  breaking change to v1.
