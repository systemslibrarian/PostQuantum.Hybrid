# ADR 0005: Multi-target net8.0 and net10.0

**Status:** Accepted

## Context

ML-KEM and ML-DSA only became public types in
`System.Security.Cryptography` starting in **.NET 10**. On .NET 8 (the
current LTS), these are not available at all.

We want PostQuantum.Hybrid to be usable on the most-deployed runtime (.NET
8 LTS, through November 2026) **and** on the newest runtime (.NET 10) where
we can use the native, FIPS-validated implementations.

## Options considered

### A. .NET 10 only

Simpler. Uses native PQ. Excludes every shop still on .NET 8 LTS — which
is most of them today.

### B. .NET 8 only, BouncyCastle for everything

Works everywhere .NET 8 runs. Doesn't take advantage of native PQ when it
exists. Locks us into BouncyCastle even when there's a strictly better
option.

### C. Multi-target net8.0;net10.0 (our choice)

Slightly more code. Both backends ship. Best implementation used on each
TFM. Wire-compatible across both.

## Decision

Multi-target `net8.0;net10.0`. On `net10.0`, ML-KEM and ML-DSA use the
native types. On `net8.0`, they use BouncyCastle. X25519 and Ed25519 use
BouncyCastle on both (the BCL does not expose them publicly yet on either
TFM).

## Rationale

- **.NET 8 LTS adoption is too large to ignore.** A library that doesn't
  work on the current LTS cannot become "the standard".
- **The complexity cost is contained.** Two thin abstractions
  (`Internal/MlKemBackend.cs`, `Internal/MlDsaBackend.cs`) hide the
  difference. The public API and wire format are identical.
- **Cross-backend interop was verified before committing.** During
  development we round-tripped keys, signatures, and ciphertexts in all
  four directions (BC sign / native verify, native sign / BC verify, BC
  encap / native decap, native encap / BC decap). All four passed.
- **When .NET 11 exposes X25519/Ed25519 natively**, we drop BouncyCastle
  on that TFM. No public-API change required.

## Consequences

- Test suite runs on both TFMs in CI; a change is not done until both pass.
- Package payload includes BouncyCastle for both TFMs (it's needed on .NET
  10 for X25519/Ed25519 too).
- Documentation must clearly state the per-TFM backend matrix; see
  `SECURITY.md` and `CLAUDE.md`.
- We commit to keeping `net8.0` until at least .NET 8 LTS ends (Nov 2026).
  Dropping it earlier would be a major-version event.
