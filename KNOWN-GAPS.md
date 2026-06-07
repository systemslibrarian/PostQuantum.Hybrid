# Known Gaps

This document is the place where we are deliberately honest about what
PostQuantum.Hybrid **does not** do. Every entry here is either (a) on the
roadmap, (b) intentionally out of scope, or (c) something we'd accept a
PR for. The README, SECURITY.md, and docs/ are not allowed to make claims
that contradict this file.

**Documentation coherence is a release gate.** Stale claims here are
treated as bugs. If you find a gap not listed here, please open an issue.

## Cryptographic gaps

### No native X25519 / Ed25519

**State:** BouncyCastle is used for X25519 and Ed25519 on both target
frameworks because `System.Security.Cryptography` does not yet expose them
publicly.

**Impact:** One unavoidable dependency on `BouncyCastle.Cryptography`.

**Plan:** Switch to native implementations on whatever .NET version first
exposes them. The public API does not need to change.

### No NIST KAT (Known Answer Test) vectors

**State:** The test suite does not include the NIST FIPS-203/204 KAT
files (they are multi-megabyte and out of scope to embed in v1). The
library implicitly cross-validates BouncyCastle vs. native by running
the same xUnit test suite on both `net8.0` (BC backend) and `net10.0`
(native backend) — wire-format drift between backends would surface as
test failures. We also relied on direct cross-backend interop probes
during development (both halves on the same TFM, four-direction
sign/verify and encap/decap), which all passed.

**Impact:** A hypothetical situation where BOTH the BCL ML-KEM/ML-DSA
implementation AND BouncyCastle's deviate from FIPS-203/204 in the
*same way* would not be caught by our tests.

**Plan:** Embed a small set of NIST KAT vectors directly so each
backend is independently validated against the published standard.
(v1.1.)

### No formal proof of the combiner

**State:** The KEM combiner is HKDF-SHA256 with transcript binding (see
[ADR 0003](docs/adr/0003-kem-combiner.md)). We argue informally that it
inherits IND-CCA security from each component; we do not have a written-up
formal proof.

**Impact:** Reviewers must accept the informal argument or reference the
broader hybrid-KEM literature.

**Plan:** Either commission a write-up or migrate to X-Wing (which *is*
formally proved) behind a new algorithm-id byte. Open question for v1.x.

### No side-channel hardening beyond what the primitives provide

**State:** The library does no constant-time comparison of our own (we
delegate to the primitives), and we do not implement countermeasures for
cache/timing/EM/power-analysis attacks beyond what BC and the BCL provide.

**Impact:** Co-located adversaries on the same physical host (shared
hosting, VM-on-VM with bad isolation) may extract key material via side
channels.

**Plan:** Document in SECURITY.md; defer hardening to deployment
guidance. We do not plan to implement library-level side-channel
mitigations.

## Feature gaps

### No PKCS#8 / SPKI key encoding

**State:** Hybrid keys serialize to a library-specific concatenated wire
format (with PEM wrapping). They do not currently produce PKCS#8 /
SubjectPublicKeyInfo blobs.

**Impact:** PostQuantum.Hybrid blobs can't be loaded into
`X509Certificate2`, OpenSSL CLI tooling, or other libraries that expect
SPKI/PKCS#8.

**Plan:** Add when IETF composite-key OIDs stabilize (drafts exist;
final OIDs pending). Tracking the
[IETF LAMPS WG](https://datatracker.ietf.org/wg/lamps/) work.

### No streaming sign/verify or streaming encapsulation

**State:** All APIs take complete byte spans. Signing a 4 GB file requires
that file fit in memory.

**Impact:** Awkward for large-payload signing.

**Plan:** Add `HybridSignature.SignPreHash(pubKey, hashAlg, hash, ...)`
once .NET native ML-DSA exposes a generic prehash mode (it currently has
`SignPreHash(string oid, ...)` but with constraints). Track .NET 11.

### No algorithm negotiation helpers

**State:** Negotiating "which hybrid combination does the other side
support" is a protocol concern, not a primitives concern. The library
exposes algorithm identifiers but does not implement any negotiation.

**Impact:** Callers must implement negotiation themselves.

**Plan:** Out of scope for the primitives package. See
`PostQuantum.Hybrid.AspNetCore` for DI-friendly key wiring patterns.

### `PostQuantum.Hybrid.AspNetCore` — initial release, missing key rotation

**State:** v1.0 ships `IHybridKemKeyProvider` and `IHybridSignatureKeyProvider`
that load keys from inline PEM or a file path. Key rotation requires a
host restart; there is no built-in `IOptionsMonitor` or
`IDataProtector`-style abstraction yet.

**Plan:** Add `IRotatingHybridKeyProvider` with file-watch and
configurable rollover windows. (v1.x.)

### `PostQuantum.Hybrid.Analyzers` — only one rule shipped

**State:** v1.0 ships PQH001 (undisposed sensitive types). The higher-
signal rules — `SharedSecret` used as a key without HKDF, verify-after-
decrypt ordering, ignored `Verify` result, AEAD without `associatedData`
binding to the KEM ciphertext — are designed but not yet implemented.

**Plan:** PQH002–PQH005 in v1.x. PQH004 (ignored Verify) is the highest
priority because it has the lowest false-positive surface.

### `dotnet new pqhybrid-app` template ships only the console scaffold

**State:** The template generates a minimal console app demonstrating
KEM + signature round trips. There is no `pqhybrid-webapi` or
`pqhybrid-messenger` template yet.

**Plan:** Add additional templates once their reference samples
(`WebApiDemo`, `SecureMessenger`) prove stable. (v1.x.)

## Test / CI gaps

### Property-style fuzz tests, but no coverage-guided fuzzing

**State:** `fuzz/PostQuantum.Hybrid.Fuzz` runs ~7,200 random/mutated
inputs per execution through every parser entry point and asserts only
expected exception types fire. This catches "parser crashes" reliably.
It is **not** coverage-guided fuzzing — there is no AFL / libFuzzer
harness driving the corpus.

**Plan:** Add a SharpFuzz harness for the parsers and run it
continuously on a separate runner. (v1.x.)

### Mutation testing config exists; CI job does not

**State:** `stryker-config.json` is checked in. CI does not run Stryker
on every PR (it's slow); we plan a periodic run.

**Plan:** Periodic GitHub Action that fails when survival rate
regresses past the configured threshold. (v1.x.)

### No benchmark baseline in CI

**State:** The benchmarks project exists (BenchmarkDotNet) but CI does
not enforce a perf-regression threshold.

**Plan:** Add a `benchmarks/baseline.json` per OS+TFM and a PR-time
job that compares. (v1.x.)

## Distribution gaps

### No signed package

**State:** Released NuGet packages are not Authenticode/PGP-signed.
Builds **are** deterministic and source-linked via SourceLink.

**Plan:** SignPath integration once the project qualifies. Sigstore
provenance attestations are also under evaluation.

### No SBOM

**State:** We do not currently publish a Software Bill of Materials with
each release.

**Plan:** Generate CycloneDX SBOM in CI; attach to GitHub releases.
(v1.x.)

### No API baseline checking

**State:** A renamed or removed public type would only be caught by
human PR review. There is no `Microsoft.CodeAnalysis.PublicApiAnalyzers`
configuration.

**Plan:** Add `PublicAPI.Shipped.txt` / `PublicAPI.Unshipped.txt` and
the analyzer. (v1.x.)
