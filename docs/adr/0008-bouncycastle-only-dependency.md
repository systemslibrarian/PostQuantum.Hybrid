# ADR 0008: Single optional dependency — BouncyCastle

**Status:** Accepted

## Context

Each transitive NuGet dependency a crypto library takes on becomes part of
its supply chain and its security review surface. We want to minimize this.

The cryptography we need:

- **X25519, Ed25519** — not yet exposed in
  `System.Security.Cryptography` on net8.0 or net10.0.
- **ML-KEM-768, ML-DSA-65** — exposed natively on net10.0
  (`System.Security.Cryptography.MLKem`, `MLDsa`); not on net8.0.
- **HKDF-SHA256, AES-GCM, SHA-256** — in the BCL on every TFM since .NET 6.
- **RandomNumberGenerator** — BCL.

## Decision

PostQuantum.Hybrid depends on exactly one third-party package:
**`BouncyCastle.Cryptography`** (version 2.6.2 or later).

No other production dependencies. The BCL provides everything else.

## Rationale

- **BouncyCastle is the canonical .NET fallback for crypto primitives
  that the BCL hasn't gotten to yet.** It is widely deployed, has a long
  security history, and is the choice every comparable .NET library makes
  for X25519/Ed25519/PQ-on-.NET-8.
- **A single dependency is auditable.** Two unrelated crypto libraries in
  the same library would be a much harder review and a confusing story
  for users worried about supply chain.
- **`BouncyCastle.Cryptography` is the official package** maintained by the
  Legion of the Bouncy Castle (not the old `BouncyCastle` package, which
  is unmaintained).

## Consequences

- The NuGet `<PackageReference>` list in `src/PostQuantum.Hybrid.csproj`
  is one entry long.
- On net10.0, the ML-KEM / ML-DSA code paths in `MlKemBackend.cs` /
  `MlDsaBackend.cs` use native types and the BC PQ code is never invoked;
  but the BC package still ships because X25519/Ed25519 always need it
  in v1.
- When .NET exposes X25519/Ed25519 natively, the BouncyCastle dependency
  becomes net8.0-only via conditional `<PackageReference>`. The public
  API surface does not change.
- Adding any other dependency requires a written justification in
  `SECURITY.md` and an ADR superseding this one.
