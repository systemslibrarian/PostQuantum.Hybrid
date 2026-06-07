# Known Gaps

This document is the place where we are deliberately honest about what
PostQuantum.Hybrid **does not** do. Every entry here is either (a) on the
roadmap, (b) intentionally out of scope, or (c) something we'd accept a
PR for. The README and SECURITY.md are not allowed to make claims that
contradict this file.

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

**Plan:** Out of scope. A separate `PostQuantum.Hybrid.AspNetCore`
package (planned) may provide opinionated helpers.

### No `PostQuantum.Hybrid.AspNetCore` package yet

**State:** No DI extensions, no helpers for typical ASP.NET patterns
(key rotation services, IDataProtector-style abstractions).

**Plan:** Ship as a separate package alongside or shortly after v1.0.

### No Roslyn analyzers yet

**State:** Common misuse patterns (using shared secret directly,
forgetting to dispose private keys, swapping verify/decrypt order) are
not detected by an analyzer.

**Plan:** Ship `PostQuantum.Hybrid.Analyzers` as a separate package.
Initial rules listed in [docs/adr/](docs/adr/) backlog.

### No `dotnet new pqhybrid` template

**State:** Starting a new app that uses PostQuantum.Hybrid means
copying from `samples/`.

**Plan:** Ship a template post-v1.0.

## Test/CI gaps

### No fuzz tests

**State:** The unit test suite includes adversarial inputs (truncated
blobs, wrong algorithm-id, tampered bytes) but is not running continuous
fuzzing.

**Plan:** Add a `fuzz/PostQuantum.Hybrid.Fuzz` project using SharpFuzz
or libFuzzer-via-CLR. (Tier 2.)

### No mutation testing

**State:** Test quality has not been validated by mutation testing
(Stryker.NET).

**Plan:** Add `stryker-config.json` and a periodic CI job. (Tier 2.)

### No benchmark baseline in CI

**State:** The benchmarks project exists (BenchmarkDotNet) but CI does
not enforce a perf-regression threshold.

**Plan:** Add a `benchmarks/baseline.json` and a PR-time job that
compares. (Tier 2.)

## Distribution gaps

### No signed package

**State:** Released NuGet packages are not Authenticode/PGP-signed and
are not produced from a reproducible build.

**Plan:** SignPath integration once the project is stable enough to
qualify; reproducible builds via `ContinuousIntegrationBuild=true` and
SourceLink (already on the v1 list).

### No SBOM

**State:** We do not currently publish a Software Bill of Materials with
each release.

**Plan:** Generate CycloneDX SBOM in CI; attach to releases. (Tier 2.)

---

If you find a gap not listed here, please open an issue. Honesty about
gaps is more useful than the appearance of completeness.
