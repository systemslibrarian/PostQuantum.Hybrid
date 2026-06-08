# Changelog

All notable changes to **PostQuantum.Hybrid** will be documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added — containerized WebApiDemo + Azure deploy scaffolding
- `samples/WebApiDemo/Dockerfile` — multi-stage build on
  `mcr.microsoft.com/dotnet/sdk:10.0-azurelinux3.0` with a conda-forge
  OpenSSL 3.5 layer so the native .NET 10 ML-KEM / ML-DSA path is
  exercised at runtime (the base image's OpenSSL 3.3.5 would
  otherwise trigger the BouncyCastle fallback per ADR 0012).
- `samples/WebApiDemo/Program.cs` mounts Swashbuckle's Swagger UI at
  the site root so the deployed URL is browser-interactive — no curl
  required. `Swashbuckle.AspNetCore 7.2.0` is referenced from the
  sample only; the library itself remains dependency-free.
- `samples/WebApiDemo/deploy.sh` — one-shot Azure Container Apps
  bootstrap (resource group, ACR, env, container app) that uses
  `az acr build` so Docker is not required locally, then pins
  `min-replicas 0 / max-replicas 1` for scale-to-zero cost control.
- `samples/WebApiDemo/DEPLOY.md` — runbook covering one-time `az`
  setup, scripted vs. manual deploys, managed-identity hardening for
  ACR pull, and teardown.
- `.github/workflows/deploy-webapidemo.yml` — push-to-main CI/CD that
  builds with ACR and updates the container app, gated on changes
  under the demo or the library source.
- `.dockerignore` at the repo root keeps the ACR build-context upload
  small.
- `samples/WebApiDemo/CUSTOM-DOMAIN.md` — Cloudflare DNS +
  Azure-managed-cert recipe for serving the live demo at
  `demo.pqhybrid.systemslibrarian.dev`. Mirrors the
  PostQuantum.Jwt playground's custom-domain doc.
- **Live demo now public at <https://demo.pqhybrid.systemslibrarian.dev>.**
  README and `PostQuantum.Hybrid.AspNetCore` README link to it; the
  package's `PackageReadmeFile` flows the link onto the NuGet listing
  page with the next published version.

## [1.0.0] — 2026-06-07

### Added — v1.x preview surface (ships in 1.0; semver-stable when refined)
- **X-Wing combiner at algorithm-id `0x02`.** New
  `HybridKemAlgorithm.X25519MlKem768XWing` enum value backed by a
  SHA3-256 combiner per draft-connolly-cfrg-xwing-kem. Opt-in only;
  `HybridKem.Default` stays on the v1 HKDF combiner. v1 component
  layout preserved — algorithm-id `0x02` is **not** byte-compatible
  with the IETF X-Wing wire format (PQ-first ordering); strict IETF
  interop is deliberately deferred to a future algorithm-id. See
  [ADR 0013](docs/adr/0013-xwing-combiner-preview.md).
- **X.509 SPKI / PKCS#8 framing.** Eight new methods total:
  `Export/ImportSubjectPublicKeyInfo` on the public-key types,
  `Export/ImportPkcs8PrivateKey` on the private-key types. DER
  envelopes use `System.Formats.Asn1`; inner bytes are the v1 wire
  format. Algorithm OIDs are placeholders under RFC 5612's IANA
  Example PEN (`1.3.6.1.4.1.32473`) — the IETF LAMPS composite-KEM /
  composite-signature drafts have not allocated final OIDs yet. See
  [ADR 0014](docs/adr/0014-spki-pkcs8-preview.md).
- **NIST `.rsp` KAT runner.** `NistKatRunner` + `NistKatParser` parse
  NIST's published key-answer-test format and cross-validate both
  BouncyCastle and the native .NET 10 backend against published
  vectors when the `PQH_NIST_KAT_DIR` environment variable points at a
  directory containing them. The weekly `nist-kats.yml` workflow
  downloads them from `vars.NIST_KAT_MIRROR` when configured. Skips
  cleanly when neither is set.

### Added — analyzer-enforced sample policy
- `samples/Directory.Build.props` adds `PostQuantum.Hybrid.Analyzers`
  as an Analyzer-typed `ProjectReference` to every sample and turns on
  `TreatWarningsAsErrors=true`. PQH001-PQH005 now run during sample
  compilation — the samples are a living regression test for the
  analyzer recommendations they showcase.
- `Directory.Build.targets` at the repo root extends the same
  policy to the library, tests, and benchmarks so analyzer regressions
  anywhere in the repo are build failures.
- `tests/Directory.Build.props` centralizes `coverlet.collector`
  across every test project so the CI line-coverage gate sees all
  suites (not just the main one).

### Added — verification surface
- **`tools/run-all-samples.ps1` (gold-standard rewrite).** Pre-build
  with `TreatWarningsAsErrors=true`, then for each sample on each TFM:
  exit code, expected-output substrings, stdout+stderr scanned for
  unhandled-exception markers, per-sample timing. Web samples boot in
  the background, hit live endpoints, parse responses by shape.
  `LargeFileEncryption` does a real `gen → seal → open → SHA-256 diff`
  round trip. `KeyRotationDemo` exercises the full zero-downtime
  rotation flow (seal at v1 → `/rotate` → assert stale envelope returns
  `410 Gone`). Failure logs are saved to a timestamped `LogDir`.
  `-CIMode` emits GitHub Actions annotations.
- **Code-coverage gate in CI.** New step under `ci.yml` installs
  `dotnet-reportgenerator-globaltool`, merges every test project's
  Cobertura report, and fails the build when combined line coverage
  drops below 75% (current measured: ~87%).
- **`NistKatTests`** also ships in-repo regression vectors (three
  seed-based vectors per algorithm) that pin SHA-256 of the derived
  public and private keys. On .NET 10 each vector is cross-checked
  against the native backend when supported.

### Added — two new samples
- **`samples/EnvelopesDemo`** — recommended starting point for
  encryption. One-call `HybridEnvelope.Seal` / `Open` and
  `SignedHybridEnvelope.Seal` / `Open`.
- **`samples/KeyRotationDemo`** — ASP.NET Core + `AddRotatingHybridKemKeys`
  + an `IHostedService` that rotates on-disk PEM files every 15 s.
  Endpoints: `GET /key`, `POST /seal`, `POST /open`, `POST /rotate`.
- All seven existing samples polished for tighter resource scoping
  (sensitive buffers cleared in `finally`, `TryImportPem` at trust
  boundaries, `encapsulation.Secret` typed wrapper instead of raw
  byte arrays).

### Added — ecosystem
- **VS Code extension** (`vscode-extension/`): nine C# snippets for
  the canonical PostQuantum.Hybrid patterns, including high-level
  `pqh-envelope` / `pqh-envelope-signed` snippets aimed at the
  Envelopes package and `pqh-aspnet-rotate` for the rotation flow.
  Every snippet body follows the analyzer-clean patterns the PQH
  rules enforce. `.vsix` builds via `vsce package`; marketplace
  publishing walkthrough in `vscode-extension/PUBLISHING.md`.
- **Consumer hardening audit script** (`scripts/audit-pqh.ps1`).
  Walks `.csproj` files under a given path, flags projects that
  reference `PostQuantum.Hybrid` without also referencing
  `PostQuantum.Hybrid.Analyzers`. Documented in `scripts/README.md`.

### Added — documentation infrastructure
- **DocFX site** under `docs-site/` auto-generates the public API
  reference from XML doc comments on `PostQuantum.Hybrid`, `Envelopes`,
  `AspNetCore`, and `TestingSupport`, plus pulls in every markdown
  doc as conceptual articles. `.github/workflows/docs.yml` deploys
  to GitHub Pages on every push to `main`.
- README gains a **Performance** section with the pinned Windows
  benchmark numbers (net8 BC vs net10 native), a **VS Code extension**
  + **audit script** callout in the ecosystem bullet, an
  **X.509 SPKI / PKCS#8 envelopes (preview)** subsection, an
  **Alternative combiner: X-Wing (preview)** subsection, and an
  expanded Documentation index covering the DocFX site,
  `samples/README.md`, `scripts/README.md`, and
  `vscode-extension/README.md`.
- Codecov + Docs badges added to README alongside the existing
  CI / CodeQL / NuGet / MIT badges.

### Added — typed exception subclasses
- `HybridKeyParseException` (Import / TryImportPem failures) and
  `InvalidCiphertextException` (ciphertext shape / algorithm mismatch).
  Both are subclasses of `PostQuantumHybridException`, so the
  existing enum-based catch surface keeps working.

### Added — Try-pattern APIs
- `HybridKemPublicKey.TryImport` / `TryImportPem`,
  `HybridKemPrivateKey.TryImport` / `TryImportPem`,
  `HybridSignaturePublicKey.TryImport` / `TryImportPem`,
  `HybridSignaturePrivateKey.TryImport` / `TryImportPem`,
  `HybridKemCiphertext.TryFromBytes`,
  `HybridKem.TryDecapsulate` (two overloads).

### Added — `HybridSharedSecret` typed wrapper
- `readonly struct HybridSharedSecret` with implicit conversion to
  `ReadOnlySpan<byte>`. Exposed via
  `HybridKemEncapsulationResult.Secret`; the existing
  `SharedSecret` `byte[]` property stays for backward compatibility.

### Internal — combiner seam + sensitive-buffer helper
- New `IKemCombiner` interface with `HkdfTranscriptKemCombiner`
  (algorithm-id `0x01`) and `XWingKemCombiner` (algorithm-id `0x02`)
  implementations; `KemCombiner.ForAlgorithm` is the dispatch
  registry.
- New internal `SecureBuffer` ref struct centralises the
  "heap-allocated short-lived byte buffer that zeroes itself on
  `Dispose`" pattern. Adopted in the hot paths of
  `HybridKem.Encapsulate` / `Decapsulate`.

### Added — IKemCombiner change note
- The combiner contract gained a `recipientClassicalPublicKey`
  parameter (`HkdfTranscriptKemCombiner` ignores it;
  `XWingKemCombiner` binds it per the X-Wing spec). Internal change
  only; the public KEM API is unaffected.

### Changed — backend selection (ship-blocker fix)
- **`MlKemBackend` and `MlDsaBackend` now fall back to BouncyCastle at
  runtime when the native .NET 10 `MLKem.IsSupported` / `MLDsa.IsSupported`
  returns `false`.** This makes the library work on `.NET 10` on Linux
  distributions whose OpenSSL does not (yet) ship ML-KEM/ML-DSA — most
  notably Ubuntu 24.04, the default GitHub Actions Linux runner. Before
  this fix, ~78 of 89 unit tests failed on Linux + `.NET 10`.
  See [ADR 0012](docs/adr/0012-runtime-backend-fallback.md). Wire format
  and public API are unchanged.
- `HybridKem.EnsureSupported` / `HybridSignature.EnsureSupported` no
  longer throw `PostQuantumHybridException(PrimitiveNotSupported)`; the
  fallback path always succeeds.

### Fixed
- `ParserFuzzTests.AssertOnlyExpectedExceptions` now allows
  `PostQuantumHybridException` (introduced in the Tier 4 typed exception
  taxonomy). The fuzz suite had been red on every CI run since that
  taxonomy shipped.
- `samples/WebApiDemo` no longer disposes the bootstrap hybrid key pairs
  before the DI options lambda runs. The lambda is invoked lazily on
  first request, so disposing the source pairs at startup caused
  `ObjectDisposedException` on every `/pub/*` and `/seal`/`/sign` call.
  The sample now reads each PEM eagerly inside a `using` block, then
  hands the strings to the options lambda.

### Added — tooling
- `tools/run-all-samples.ps1` exercises every sample (BasicDemo,
  KemEncryption, SignedDocument, KeyPersistence, SecureMessenger,
  LargeFileEncryption, WebApiDemo) on every target framework and
  asserts each one's happy path and tamper-detection step both work.
  LargeFileEncryption drives `gen -> seal -> open` and SHA-256-diffs
  the recovered file. WebApiDemo is started in the background and
  exercised via GET and POST. Returns non-zero on any failure with a
  per-sample summary.

### Added — analyzer code-fixes
- Code-fix providers for **PQH002**
  (`HkdfWrapSharedSecretCodeFix` — wraps a raw `SharedSecret` arg with
  `HKDF.DeriveKey(...)`), **PQH003**
  (`MoveVerifyBeforeDecapsulateCodeFix` — reorders verify before
  decapsulate), and **PQH005**
  (`AddAssociatedDataCodeFix` — adds `associatedData:` arg with auto-
  discovery of the KEM ciphertext expression in scope).

### Added — library (`PostQuantum.Hybrid`)
- Hybrid KEM (`HybridKem`) combining **X25519 + ML-KEM-768** with an
  HKDF-SHA256 combiner that binds both ciphertexts into the derived
  shared secret.
- Hybrid digital signatures (`HybridSignature`) combining **Ed25519 +
  ML-DSA-65** with concatenated signatures requiring both schemes to
  verify.
- Versioned, fixed-size wire format for every artifact (algorithm-id
  byte + classical part + post-quantum part).
- Raw byte and PEM serialization for all public/private keys.
- `IDisposable` private-key and encapsulation-result types with
  explicit zeroization of sensitive buffers.
- Multi-targets `net8.0` and `net10.0`:
  - `net10.0`: uses native `System.Security.Cryptography.MLKem` /
    `MLDsa`.
  - `net8.0`: uses BouncyCastle's `MLKemKeyPairGenerator` /
    `MLDsaSigner`.
  - Wire format is identical across both backends.
- Source-linked, deterministic builds. Symbol package (`.snupkg`)
  publication.

### Added — analyzers (`PostQuantum.Hybrid.Analyzers`)
- New package. Roslyn analyzers for build-time misuse detection.
- **PQH001** (Warning): `HybridKemKeyPair` /
  `HybridKemPrivateKey` / `HybridSignatureKeyPair` /
  `HybridSignaturePrivateKey` / `HybridKemEncapsulationResult`
  declared without `using`.

### Added — templates (`PostQuantum.Hybrid.Templates`)
- New package. `dotnet new pqhybrid-app` template scaffolds a console
  app pre-wired with `PostQuantum.Hybrid` and
  `PostQuantum.Hybrid.Analyzers`.

### Added — samples
- `BasicDemo` — shortest possible KEM + signature round trip.
- `KemEncryption` — KEM → HKDF → AES-GCM canonical encryption flow.
- `SignedDocument` — detached signature with publish/verify split.
- `KeyPersistence` — PEM save/load with disposal.
- `SecureMessenger` — end-to-end signed-and-encrypted Alice → Bob flow.

### Added — tests
- 85 unit tests across 9 test classes covering: round-trips, tamper
  detection, algorithm-id checks, serialization, dispose semantics,
  length validation, edge cases (empty / 1 MiB messages, Unicode),
  concurrency, end-to-end scenarios.
- 9 property-style fuzz tests in `fuzz/PostQuantum.Hybrid.Fuzz` driving
  ~7,200 random/mutated inputs per run.
- 8 analyzer tests using a hand-rolled in-memory harness.
- 196 total test runs across all projects and TFMs.

### Added — benchmarks
- BenchmarkDotNet suite (`benchmarks/PostQuantum.Hybrid.Benchmarks`)
  measuring keygen / encap / decap / sign / verify / serialization on
  both target frameworks.

### Added — documentation
- README, CHANGELOG, SECURITY, CONTRIBUTING, CLAUDE.md.
- `docs/SPEC.md` — full normative wire-format specification.
- `docs/design.md` — rationale for every major design choice.
- `docs/THREAT-MODEL.md` — in/out-of-scope threats + operational
  guidance.
- `docs/adr/0001..0008` — architecture decision records.
- `HARDENING-CHECKLIST.md` — production deployment checklist.
- `KNOWN-GAPS.md` — honest accounting of what v1 does and does not do.
- `src/LLM-USAGE.md` — prescriptive guide for AI assistants.
- `src/SECURE-USAGE.md` — prescriptive secure-usage patterns.

### Added — repo infrastructure
- `.github/workflows/ci.yml` — build + test on ubuntu/windows/macos,
  both TFMs, plus vulnerable-packages and pack jobs.
- `.github/workflows/codeql.yml` — weekly + PR-time CodeQL analysis.
- `.github/workflows/release.yml` — pack + push to NuGet on `v*` tags.
- `.github/dependabot.yml` — weekly NuGet and Actions updates.
- `.github/CODEOWNERS`, PR template, issue templates.
- `.well-known/security.txt` (RFC 9116).
- `tools/run-all.ps1`, `tools/pack-local.ps1`, `tools/check-format.ps1`.
- `LICENSE` (MIT), `.editorconfig`, `.gitignore`, `global.json`,
  `Directory.Build.props`.

### Security
- ML-KEM implicit rejection: malformed ciphertexts yield a pseudorandom
  secret rather than throwing, so downstream decryption fails
  authentically.
- Empty-context FIPS-204 pure ML-DSA signing, matching .NET native
  defaults.
- Cross-backend interop verified during development: keys/signatures/
  ciphertexts produced by BouncyCastle on net8.0 are accepted by native
  .NET on net10.0 and vice versa, in all four directions.
