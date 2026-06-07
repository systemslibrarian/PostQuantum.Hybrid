# ADR 0012: Runtime fallback to BouncyCastle when native ML-KEM/ML-DSA is unavailable

**Status:** Accepted

## Context

[ADR 0006](0006-backend-abstraction.md) chose compile-time backend selection
via `#if NET10_0_OR_GREATER`: on .NET 10 the library called the native
`System.Security.Cryptography.MLKem` / `MLDsa` types unconditionally; on .NET
8 it used BouncyCastle. The `IsSupported` property forwarded
`MLKem.IsSupported` / `MLDsa.IsSupported`, and `HybridKem.EnsureSupported`
threw `PostQuantumHybridException` when those returned `false`.

That decision was made on the assumption that "`MLKem.IsSupported == true`"
held wherever .NET 10 was installed. It does not. .NET 10's ML-KEM and
ML-DSA implementations are thin wrappers around OpenSSL providers, and at
the time of v1.0:

- Ubuntu 24.04 (the default GitHub Actions Linux runner) ships OpenSSL 3.0.
  ML-KEM and ML-DSA are not in OpenSSL 3.0 — they require OpenSSL 3.5+ with
  the relevant provider, or a separate provider like liboqs.
- macOS bundles its own crypto stack; PQ algorithms are not exposed on
  current versions either.
- Windows 11 24H2 (current GitHub Actions Windows runner) **does** expose
  them through CNG.

The practical effect was that on every Linux runner using .NET 10, every
call into `HybridKem.GenerateKeyPair` threw
`PostQuantumHybridException: ML-KEM is not supported on this platform`,
which surfaced as **78 of 89 main-suite test failures** (plus most of the
Envelopes, AspNetCore, and TestingSupport suites) once CI noticed.

## Options considered

### A. Document Linux + .NET 10 as unsupported

Honest, but excludes a large population. .NET 10 is the modern target;
"runs on .NET 10 but only on Windows and macOS-with-extras" is a hostile
shape for an "as long as either primitive holds" library.

### B. Runtime fallback to BouncyCastle when native isn't supported

Keep the public API and wire format identical. On .NET 10, check
`MLKem.IsSupported` at runtime: if `true`, use native (the win); if `false`,
use the same BouncyCastle code path the .NET 8 backend uses. The
BouncyCastle code is already shipped (we use it for X25519/Ed25519 on every
TFM anyway), so the cost of always compiling it on .NET 10 is small.

### C. Probe-and-throw with a clearer error and a "preview install ML-KEM" doc page

Same as the v1.0-pre-fix behavior plus better docs. Doesn't actually make
the library work where developers will try to run it.

## Decision

Option **B**: runtime fallback.

Both `MlKemBackend` and `MlDsaBackend` now compile the BouncyCastle path
on every TFM. On .NET 10, each operation calls native when
`MLKem.IsSupported` / `MLDsa.IsSupported` is `true`, otherwise falls back
to BouncyCastle. `IsSupported` on each backend becomes a hardcoded `true`
(BouncyCastle is always available); `HybridKem.EnsureSupported` and
`HybridSignature.EnsureSupported` no longer throw on the "primitive not
supported" path.

## Rationale

- **Wire format is identical across backends.** This was already a
  hard contract from ADR 0006; the fallback inherits it for free. A blob
  written on Linux+.NET 10 (BC) loads on Windows+.NET 10 (native) and on
  any .NET 8 deployment.
- **No public API change.** Same types, same exception taxonomy, same
  semantics. `IsSupported` stays `true` either way because the user can
  always succeed.
- **"Native BCL first" is preserved at runtime granularity.** The rule
  in `CLAUDE.md` originally read "use native when the TFM exposes it" —
  re-interpreted as "use native when the runtime exposes it on this
  machine," the spirit is intact.
- **Performance difference is small enough to ignore for v1.0.** Native
  ML-KEM-768 in OpenSSL 3.5+ is roughly the same order of magnitude as
  BouncyCastle's managed implementation — both are sub-millisecond.
  Side-channel resistance is at parity (both delegate to vetted
  implementations; we add no custom arithmetic).

## Consequences

- BouncyCastle stays a required dependency on every TFM. (It already was —
  X25519 and Ed25519.)
- The compiled `net10.0` DLL grows slightly because both BC and native
  call sites are emitted. The cost is small; the BC code is already linked
  for the curve operations.
- The benchmark workflow on Linux measures the BC backend (because native
  isn't available), not the native one. The per-OS baseline scheme already
  anticipated this; the Windows baseline remains canonical for native
  performance, and Linux numbers are recorded for tracking the BC path.
- `DeterministicKeyGenerationTests.MlKem768_FromSeed_BackendsAgreeOnPublicKey`
  and its ML-DSA sibling are gated on `MLKem.IsSupported` / `MLDsa.IsSupported`
  at runtime: on environments where there is no native backend to
  cross-check against, the test returns early rather than failing.
- Users who want to *force* the native backend (and surface a clean error
  if it isn't available) can probe `System.Security.Cryptography.MLKem.IsSupported`
  themselves at startup; the library will not gate on it on their behalf.
