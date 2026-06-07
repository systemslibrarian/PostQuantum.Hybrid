# ADR 0013: X-Wing combiner at algorithm-id 0x02 (preview)

**Status:** Accepted (preview)

## Context

[ADR 0003](0003-kem-combiner.md) picked HKDF-SHA256 with transcript binding
as the v1 KEM combiner. The argument was that it inherits IND-CCA security
from each component KEM informally; we have no formal proof.

The X-Wing construction
([draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/))
specifies a SHA3-256-based combiner explicitly for X25519 + ML-KEM-768
that has a published security analysis. v1 users who want that property
should be able to opt in without forking the library or jumping
algorithms entirely.

[ADR 0012](0012-runtime-backend-fallback.md) had already added the
`IKemCombiner` seam; this ADR uses it.

## Decision

Introduce a second algorithm-id value, `HybridKemAlgorithm.X25519MlKem768XWing = 2`,
backed by `XWingKemCombiner` (an `IKemCombiner` implementation that
produces the derived secret as:

```
SS = SHA3-256( label6 || ss_M || ss_X || ct_X || pk_X )
```

where `label6` is the 6-byte literal `\x5c\x2e\x2f\x2f\x5e\x5c` from
section 5 of the X-Wing draft, `ss_M` is the ML-KEM-768 shared secret,
`ss_X` is the X25519 shared secret, `ct_X` is the X25519 "ciphertext"
(sender's ephemeral public key), and `pk_X` is the recipient's X25519
public key.

The v1 algorithm-id (`X25519MlKem768 = 1`, HKDF combiner) remains the
default for `HybridKem.GenerateKeyPair()` and for the
`HybridKem.Default` property; X-Wing is strictly opt-in via
`GenerateKeyPair(HybridKemAlgorithm.X25519MlKem768XWing)`.

## Honest scope: "X-Wing combiner over the v1 wire shape", NOT IETF X-Wing interop

PostQuantum.Hybrid v1 orders hybrid wire-format components
**classical-first** at every algorithm-id:

```
[ 1B algorithm id ] [ X25519 ... ] [ ML-KEM ... ]
```

The IETF X-Wing draft orders components **post-quantum-first**:

```
[ ML-KEM ... ] [ X25519 ... ]
```

That means a `HybridKemPublicKey` exported at algorithm-id `0x02` is NOT
byte-compatible with an X-Wing implementation in any other language. To
spell this out:

- An X-Wing IETF reference implementation could not decapsulate
  ciphertexts we produce at id `0x02` (different byte ordering of the
  ML-KEM and X25519 components inside the blob).
- Conversely, we cannot parse a blob another library produces in the
  IETF X-Wing wire format using id `0x02`.

What algorithm-id `0x02` *does* give you is the X-Wing combiner formula
applied to a PostQuantum.Hybrid v1-shaped key/ciphertext, so callers
inside this library's ecosystem get the X-Wing combiner's analysis
without needing to migrate wire formats.

Strict IETF X-Wing wire-format interop is deliberately deferred to a
later algorithm-id (likely `0x03`) so the ordering split is visible at
the algorithm-id level.

## Rationale

- **Seam already exists.** `IKemCombiner` from
  [ADR 0012](0012-runtime-backend-fallback.md)'s sibling refactor lets
  us add the combiner without touching `HybridKem` beyond a registry
  dispatch.
- **Both combiners coexist.** Existing v1 artifacts continue to work
  unchanged at id `0x01`. New callers opt in to id `0x02` by passing the
  enum value to `GenerateKeyPair`.
- **Default stays HKDF.** The `HybridKem.Default` property still returns
  `X25519MlKem768`. Test `HybridKem_Default_StaysX25519MlKem768` defends
  against accidental default flips.
- **Implementation uses BouncyCastle's `Sha3Digest`.** The BCL
  `System.Security.Cryptography.SHA3_256` requires Windows 11 24H2 or an
  OpenSSL build with SHA3 — we cannot rely on it across the support
  matrix. BC's SHA3 implementation has been audited and is always
  available because we already depend on BouncyCastle.

## Consequences

- The `HybridKemAlgorithm` enum gains one public value. Documented as a
  preview member: subject to refinement before v2.
- `KemCombiner.ForAlgorithm` dispatches to the right combiner.
  `IKemCombiner.Combine` grew a `recipientClassicalPublicKey` parameter
  — `HkdfTranscriptKemCombiner` ignores it; `XWingKemCombiner` requires
  it. `HybridKem.Decapsulate` derives the recipient's X25519 public key
  from the private seed inside the same `SecureBuffer` scope so the
  derivation does not leak material.
- `HybridKemPublicKey.Import`, `HybridKemPrivateKey.Import`, and
  `HybridKemCiphertext.FromBytes` now accept both algorithm ids.
- The XML doc on the enum value is explicit about the preview status
  and the wire-format scope.
- An ADR for a future strict IETF X-Wing interop algorithm-id (`0x03`?)
  will reference this one. Until that lands, v1.x users that want
  cross-implementation interop should stay on `X25519MlKem768`.
