# Roadmap

What's planned for PostQuantum.Hybrid after v1.0. This is directional,
not a contract — file an issue if something here matters to you and is
running late.

## v1.x (additive only — no wire-format changes)

### High priority

- **NIST KAT vector tests.** Embed a small set of FIPS-203 and
  FIPS-204 known-answer test vectors so each backend is validated
  against the standard directly, not just cross-validated against the
  other.
- **`PostQuantum.Hybrid.AspNetCore` package.** DI extensions for loading
  keys from configuration, `IHybridKeyProvider` abstraction, and
  `IDataProtector`-style hybrid blob encryption.
- **More analyzers.**
  - PQH002: shared secret used as AEAD key without HKDF.
  - PQH003: decapsulate-before-verify in sign-then-encrypt code paths.
  - PQH004: algorithm-id byte stripped on serialization.
- **Performance regression gate in CI.** Compare benchmarks against a
  pinned baseline; fail PRs that regress >5%.

### Medium priority

- **PKCS#8 / SubjectPublicKeyInfo encoding** once IETF composite-key
  OIDs stabilize. (Tracking LAMPS WG.)
- **Streaming sign/verify** once .NET native ML-DSA exposes a generic
  prehash mode.
- **SLH-DSA support** as an additional algorithm-id combination
  (`Ed25519SlhDsaSha2_128s` for hash-based defense in depth).
- **X-Wing combiner** as an additional KEM algorithm-id combination
  for callers who want bit-compatibility with the X-Wing spec.

### Lower priority

- **Coverage-guided fuzzing** via SharpFuzz / AFL.NET in a separate
  harness.
- **Mutation testing** via Stryker.NET in a periodic CI job.
- **CycloneDX SBOM** published with each release.
- **Reproducible-build verification** in CI.
- **SignPath / Sigstore signing** of release packages.
- **Reference port checklist** for implementers in other languages.

## v2 (the only path to a breaking change)

We do not currently plan a v2. The wire-format design — single-byte
algorithm-id at the front of every blob — means new algorithms and new
combinations are minor-version additions, not breaking changes.

The only scenarios that would force a v2:

- A fundamental cryptanalytic break in *both* X25519 *and* ML-KEM-768
  (or *both* Ed25519 *and* ML-DSA-65), requiring a new default and
  default-deprecation of the old.
- Removal of `BouncyCastle.Cryptography` dependency on `net8.0` (only
  possible if Microsoft backports `MLKem` / `MLDsa` to .NET 8 — extremely
  unlikely).

If v2 happens, v1 will be supported for at least 12 months in
parallel.

## Cancelled / not happening

- **`alg: none`-equivalent unsigned path.** Not now, not ever.
- **Caller-selectable IND-CPA mode.** ML-KEM uses IND-CCA Fujisaki-Okamoto
  transform internally; we don't expose a downgrade.
- **HMAC-based MAC mode for the KEM combiner output.** Use HKDF + AEAD.

## How decisions get made

1. **Open an issue** describing the use case.
2. **Discuss tradeoffs** publicly. Cryptographic changes get extra
   scrutiny; algorithm additions in particular need a written argument
   for why the existing combination is insufficient.
3. **Write an ADR** under `docs/adr/` capturing the decision and
   rationale, even if the answer is "no".
4. **Implement behind a new algorithm-id** when the change touches the
   wire format. Never modify an existing algorithm's behavior.
