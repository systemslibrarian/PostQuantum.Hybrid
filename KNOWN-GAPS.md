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

### Embedded regression vectors + NIST .rsp runner ship; vector fetch is operational

**State:** Two layers of FIPS-203/204 validation now ship:

1. `NistKatTests` ships three in-repo seed-based regression vectors per
   algorithm. Each vector pins the SHA-256 of both the derived public
   key and the derived private key. On `net10.0` the same seeds are
   fed through the native `System.Security.Cryptography.MLKem` /
   `MLDsa` paths (when the OS exposes them) and the resulting public
   keys are asserted bit-equal between backends.

2. `NistKatRunner` parses NIST's published `.rsp` KAT format and
   validates that BouncyCastle (and, where available, the native
   .NET 10 backend) derives the published bytes from each vector's
   seed. The runner is gated on the `PQH_NIST_KAT_DIR` environment
   variable: when unset (the default — most local runs and the
   regular CI matrix), every test in the runner returns early. The
   weekly `nist-kats.yml` workflow downloads the files from
   `vars.NIST_KAT_MIRROR` when configured and runs the runner against
   them.

**Impact (residual):** Only the *operational* gap remains. The runner
itself is in place; for it to actually compare against the real NIST
published vectors, a maintainer needs to set `vars.NIST_KAT_MIRROR`
on the repo (a URL serving `ML-KEM-768.zip` / `ML-DSA-65.zip`
containing the NIST `.rsp` files). Without that, the runner skips
cleanly and validation falls back to the in-repo regression vectors.

**Plan:** Stand up the mirror (or fold the .rsp files into the repo
as test fixtures if their license permits) so the published-vector
check runs unconditionally on the weekly schedule.

### No formal proof of the v1 default combiner (but X-Wing preview ships)

**State:** The v1 default KEM combiner is HKDF-SHA256 with transcript
binding (see [ADR 0003](docs/adr/0003-kem-combiner.md)). We argue
informally that it inherits IND-CCA security from each component; we
do not have a written-up formal proof. The X-Wing combiner — which
*does* have a published security analysis — ships at algorithm-id
`0x02` as a preview opt-in via
`HybridKemAlgorithm.X25519MlKem768XWing`; see
[ADR 0013](docs/adr/0013-xwing-combiner-preview.md).

**Impact:** Reviewers of the v1 default surface still must accept the
informal argument or reference the broader hybrid-KEM literature.
Callers who want the formal property today can opt in to
algorithm-id `0x02`.

**Plan:** Either commission a write-up for the v1 default, or promote
the X-Wing combiner to the default in a future major release. The v1
default remains HKDF for backward compatibility with shipped artifacts.

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

### PKCS#8 / SPKI framing ships with placeholder OIDs (preview)

**State:** `HybridKemPublicKey.ExportSubjectPublicKeyInfo()` /
`ImportSubjectPublicKeyInfo`, `HybridKemPrivateKey.ExportPkcs8PrivateKey()`
/ `ImportPkcs8PrivateKey`, and the analogous four methods on the
signature key types all ship in v1.x. The DER encoding follows X.509
SPKI and PKCS#8 v1 verbatim; the inner key bytes are the existing
PostQuantum.Hybrid wire format including the algorithm-id byte. See
[ADR 0014](docs/adr/0014-spki-pkcs8-preview.md).

**Impact (residual):** The algorithm OIDs are placeholders under the
IANA Example PEN `1.3.6.1.4.1.32473` (RFC 5612). The IETF LAMPS WG's
composite-KEM / composite-signature drafts have not finalized their
OIDs yet; when they do, the codec will accept both the placeholder
OIDs (for backward compatibility with early adopters) and the
IETF-allocated values. Cross-implementation interop today is
limited to other PostQuantum.Hybrid consumers — third-party tools
that key OID lookups against the IETF registries will not recognise
our preview OIDs.

**Plan:** Watch
[IETF LAMPS WG](https://datatracker.ietf.org/wg/lamps/). When the
drafts allocate final OIDs, add them as additional accepted values
in `Internal.Pkcs8SpkiCodec` and document the migration in CHANGELOG.

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

### `PostQuantum.Hybrid.AspNetCore` — feature-complete for v1.0

**State:** v1.0 ships `IRotatingHybridKemKeyProvider` /
`IRotatingHybridSignatureKeyProvider` with `FileSystemWatcher`-based
atomic key rotation, plus a `HybridEnvelopeDataProtector` that adapts
the hybrid envelope construction to ASP.NET Core's `IDataProtector`
pipeline with per-purpose AAD binding.

**Plan:** No further follow-up planned for v1.0. v1.x may add a
versioned multi-key reader for read-old-write-new rotation patterns.

### `PostQuantum.Hybrid.Analyzers` — five rules shipped, more possible

**State:** v1.0 ships PQH001 (undisposed sensitive types), PQH002
(SharedSecret without HKDF), PQH003 (Decapsulate-before-Verify
ordering), PQH004 (ignored Verify result), and PQH005 (AEAD without
KEM-ciphertext-as-associatedData binding). Code-fix providers are
included for PQH001 (auto-insert `using`) and PQH004 (auto-wrap in
`if (!...) throw`).

**Plan:** Additional rules will be added if real-world misuse patterns
emerge. Code-fixes for PQH002–PQH005 are good follow-ups.

## Test / CI gaps

### Coverage-guided fuzzing scaffold shipped, no continuous runner

**State:** `fuzz/PostQuantum.Hybrid.Fuzz` runs ~7,200 random/mutated
inputs per execution through every parser entry point and asserts only
expected exception types fire. `fuzz/PostQuantum.Hybrid.Fuzz.Sharp`
provides a SharpFuzz harness with 7 targets ready to drive under AFL
or libFuzzer. We do not yet operate a dedicated machine continuously
running the harness.

**Plan:** Stand up a long-running fuzz worker (separate from CI) and
publish discovered corpus inputs back to the repo's seed corpus.

### Mutation testing CI shipped with fixed threshold gate

**State:** `.github/workflows/mutation.yml` runs Stryker weekly and
uploads HTML/JSON reports as artifacts. `stryker-config.json` sets
`thresholds.break = 70`, so the workflow fails when the mutation score
drops below 70% — the regression gate is wired with a fixed bound.
Per-PR baseline-comparison ("worse than last main run") is **not** in
place; we rely on the absolute threshold instead.

**Plan:** Tighten the threshold as the score climbs (today's score is
the floor we keep raising). Optionally add a per-PR baseline diff if
the fixed-threshold approach proves too coarse.

### Benchmark baseline + comparison shipped, Linux baseline pending

**State:** `.github/workflows/benchmark.yml` runs BenchmarkDotNet
weekly on both TFMs. `tools/compare-benchmarks.ps1` compares the
results against pinned `benchmarks/baseline-{tfm}-windows.json`
files (default regression threshold 25%) and exits non-zero on
regression. CI invokes the comparison on Linux as
`continue-on-error: true` until we capture a per-OS baseline (Linux
numbers differ from Windows numbers measurably).

**Plan:** Capture a Linux baseline from a run on a standard GH
runner and switch the comparison from `continue-on-error` to a hard
fail.

## Distribution gaps

### No signed package

**State:** Released NuGet packages are not Authenticode/PGP-signed.
Builds **are** deterministic and source-linked via SourceLink.

**Plan:** SignPath integration once the project qualifies. Sigstore
provenance attestations are also under evaluation.

### SBOM CI workflow shipped

**State:** `.github/workflows/sbom.yml` generates a CycloneDX SBOM per
package on release and attaches them as release assets.
**No follow-up required for v1.0.**
(v1.x.)

### API baseline checking shipped

**State:** `Microsoft.CodeAnalysis.PublicApiAnalyzers` is wired into
`src/PostQuantum.Hybrid/PostQuantum.Hybrid.csproj` and the public
surface is locked in `src/PostQuantum.Hybrid/PublicAPI.Shipped.txt` /
`PublicAPI.Unshipped.txt`. Renaming, removing, or adding a public type
is now a build-time error until the appropriate API file is updated.

**No follow-up required for v1.0.**
