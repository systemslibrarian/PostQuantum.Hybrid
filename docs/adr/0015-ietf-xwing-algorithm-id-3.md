# ADR 0015: Strict IETF X-Wing interop at algorithm-id 0x03

**Status:** Accepted (preview — tracks draft-connolly-cfrg-xwing-kem-10)

## Context

Algorithm-id `0x02` (`X25519MlKem768XWing`) uses the X-Wing *combiner*
(SHA3-256 over `ss_M || ss_X || ct_X || pk_X || label`) but keeps the
PostQuantum.Hybrid v1 conventions everywhere else: classical-first
component order on the wire, an independently generated X25519 key and
ML-KEM key, and a 2432-byte expanded private key. A `0x02` blob is
therefore **not** interoperable with other X-Wing implementations
(CIRCL, libcrux, rustls), even though the combiner now matches the
draft exactly (see ADR 0013 / the 0x02 combiner fix).

The IETF draft defines X-Wing as a complete KEM, not just a combiner:

- The decapsulation key is a single **32-byte seed**.
  `expanded = SHAKE-256(seed, 96)`; `(pk_M, sk_M) =
  ML-KEM-768.KeyGen_internal(expanded[0:64])`; `sk_X = expanded[64:96]`;
  `pk_X = X25519(sk_X, basepoint)`.
- Encapsulation key: `pk_M || pk_X` (1216 bytes, **ML-KEM first**).
- Ciphertext: `ct_M || ct_X` (1120 bytes, ML-KEM first).
- Shared secret: `SHA3-256(ss_M || ss_X || ct_X || pk_X ||
  "\x5c\x2e\x2f\x2f\x5e\x5c")`.
- ASN.1: `id-XWing = 1.3.6.1.4.1.62253.25722`, with *no* inner ASN.1
  wrapping — the SPKI BIT STRING is the raw 1216-byte key and the
  PKCS#8 OCTET STRING is the raw 32-byte seed.

The draft ships official test vectors (`spec/test-vectors.json`) and
CIRCL-generated x509 fixtures, so conformance is mechanically checkable.

## Decision

Add a third KEM algorithm, `HybridKemAlgorithm.XWing = 3`, that is
**byte-for-byte IETF X-Wing** behind the 1-byte algorithm-id prefix:

| Object | Layout | Size |
|---|---|---|
| Public key | `0x03 \|\| pk_M \|\| pk_X` | 1217 B |
| Private key | `0x03 \|\| seed` | 33 B |
| Ciphertext | `0x03 \|\| ct_M \|\| ct_X` | 1121 B |

Stripping the prefix yields genuine IETF X-Wing bytes; prepending
`0x03` to foreign X-Wing material makes it importable. The PQ-first
component order and the seed-only private key are what distinguish
`0x03` from `0x02` on the wire (public key and ciphertext total sizes
coincide at 1217/1121 — the algorithm-id byte is the discriminator,
which is why imports must dispatch on algorithm-id before length).

- **Key generation:** draw 32 random bytes, expand per the draft.
  ML-KEM keygen-from-seed uses the native
  `MLKem.ImportPrivateSeed` on .NET 10 and BouncyCastle
  `MLKemPrivateKeyParameters.FromSeed` (64-byte `d || z`) on .NET 8 /
  fallback. SHAKE-256 comes from BouncyCastle `ShakeDigest(256)` on
  both TFMs (the BCL's SHAKE is not available across the whole support
  matrix).
- **Encapsulation** reuses the existing algorithm-agnostic flow; the
  combiner registry maps `3` to the existing `XWingKemCombiner`.
- **Decapsulation** re-expands the seed each call (the draft's
  reference semantics). ML-KEM implicit rejection is preserved by the
  backends.
- **SPKI/PKCS#8** use the real `id-XWing` OID with the raw IETF inner
  bytes (1216-byte key / 32-byte seed, no `0x03` prefix), so exported
  envelopes are directly consumable by other X-Wing stacks. The
  placeholder-PEN OIDs of ADR 0014 remain for algorithm-ids 1 and 2.
- **Conformance tests** vendor the draft's official vectors
  (seed/eseed/pk/ct/ss KATs via public import + decapsulate paths) and
  the CIRCL x509 fixtures (`xwing.pub` / `xwing.priv`).

`0x02` stays supported and unchanged; its docs steer new interop work
to `0x03`.

## Rationale

- **Wire-format stability is sacred.** IETF X-Wing semantics cannot be
  retrofitted onto `0x02` (different component order, different private
  key) — a new algorithm-id is exactly what the versioning rule in
  CLAUDE.md / ADR 0007 prescribes.
- **Seed-only private keys are the draft's deliberate design** (fully
  deterministic expansion, nothing-up-my-sleeve, tiny at-rest secrets).
  Diverging would forfeit interop with every other implementation.
- **No hand-rolled crypto.** SHAKE-256, X25519, and ML-KEM-from-seed
  all come from BouncyCastle or the BCL; the only new code is glue and
  byte layout.
- **A real OID is finally legitimate here.** Unlike the LAMPS composite
  drafts (still unallocated), `id-XWing` is concretely assigned in the
  X-Wing draft's ASN.1 module and already used in the wild (CIRCL).

## Consequences

- New public surface: `HybridKemAlgorithm.XWing = 3`
  (PublicAPI.Unshipped.txt entry; XML docs flag preview status until
  the draft becomes an RFC — if a later draft changes the scheme, a
  new algorithm-id will be allocated rather than mutating `0x03`).
- `MlKemBackend` gains seed-based operations
  (public-key derivation and decapsulation from a 64-byte `d || z`).
- Private-key material handling: the 32-byte seed is the secret;
  expanded intermediates (`expanded[96]`, `sk_X`, ML-KEM handles) are
  zeroed/disposed after each use like all other key material.
- Import dispatch order changes from length-first to
  algorithm-id-first, since `0x03` private keys are 33 bytes, not 2433.
  Existing v1/v2 blobs parse exactly as before.
- SPEC.md gains a `0x03` section; README install/interop matrix and
  CHANGELOG updated in the same PR.
