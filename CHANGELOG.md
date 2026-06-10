# Changelog

All notable changes to **PostQuantum.Hybrid** will be documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed — **BREAKING for the `0x02` X-Wing preview**: combiner label position
- The `0x02` (`X25519MlKem768XWing`, preview) combiner hashed the 6-byte
  X-Wing label *first*; the IETF draft moved it to the *end* in draft-03
  ("Move label at the end") and it has stayed there through draft-10. The
  combiner now matches the current draft:
  `SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)`.
- **Impact:** shared secrets derived at `0x02` by v1.0.1 differ from those
  derived by this version. Keys and ciphertexts still parse (wire layouts
  are unchanged); mixed-version peers fail closed at the AEAD layer. The
  default `0x01` algorithm is unaffected. `0x02` is a preview member,
  documented as subject to refinement — see the amendment in
  [ADR 0013](docs/adr/0013-xwing-combiner-preview.md) and the History note
  in `docs/SPEC.md`.

### Added — continuous fuzzing in CI
- New `.github/workflows/fuzz.yml`: weekly AFL++ runs of the SharpFuzz
  harness, one time-boxed matrix job per parser target (7 targets), failing
  on any crash and uploading findings. The harness gained a `make-corpus`
  mode that generates one minimal-valid seed blob per target, replacing the
  (previously empty) checked-in corpus.

### Added — cross-implementation interop checks (Go stdlib)
- New `interop/` suite + `.github/workflows/interop.yml`: weekly CI proves
  the ML-KEM-768 backend agrees with Go's standard-library `crypto/mlkem`
  on fresh random seeds — identical keygen from the same seed, plus
  encapsulate/decapsulate round-trips in both directions, against
  BouncyCastle on both TFMs and the native .NET 10 backend where the OS
  exposes it. Catches "both our backends share the same bug" failures the
  KAT suites cannot. ML-DSA interop is planned (`KNOWN-GAPS.md`).

### Added — NIST ACVP vectors vendored; published-KAT validation now unconditional
- New `NistAcvpKatTests` validates BouncyCastle (and the native .NET 10
  backend where supported) against vendored NIST ACVP gen-val vectors for
  the final FIPS 203/204 standards: ML-KEM-768 keyGen + decapsulation
  (incl. implicit rejection), ML-DSA-65 keyGen + sigVer (incl. NIST's
  negative vectors). Fixtures live under
  `tests/PostQuantum.Hybrid.Tests/fixtures/nist-acvp/` with provenance in
  `NOTICE.md`; refresh with `tools/fetch-nist-acvp.ps1`. The
  `vars.NIST_KAT_MIRROR` operational gap is closed — published-vector
  validation now runs in every test run.

### Added — Wycheproof negative vectors vendored
- New `WycheproofTests` runs the Wycheproof (C2SP) vectors against the
  classical primitives the library delegates to and against the library's
  own hybrid paths: X25519 agreement (including fail-closed rejection of
  low-order/all-zero shared secrets, asserted both at the BouncyCastle
  primitive and through `HybridKem.Encapsulate`), Ed25519 signature
  malleability/encoding negatives driven through `HybridSignature.Verify`
  via grafted hybrid blobs, and ML-DSA-65 verify negatives on both
  backends. Fixtures live under
  `tests/PostQuantum.Hybrid.Tests/fixtures/wycheproof/` (Apache-2.0, see
  its `NOTICE.md`); refresh with `tools/fetch-wycheproof.ps1`.

### Fixed — ML-KEM seed ordering in the legacy `.rsp` KAT runner
- `NistKatRunner` concatenated separate `z`/`d` fields as z‖d; FIPS 203
  (and BouncyCastle `FromSeed` / .NET `ImportPrivateSeed`) define the
  64-byte seed as **d‖z**. Latent only — no published `.rsp` files for
  the final standards exist, so the path had never run against real
  split-field vectors.

### Fixed — SPEC.md documents algorithm-id `0x02`
- `docs/SPEC.md` now lists KEM algorithm-id `0x02`
  (`X25519MlKem768XWing`, preview) in the identifier table and specifies
  its SHA3-256 combiner formula. The id shipped in ADR 0013 but the
  normative spec was never updated — a doc-coherence bug.

### Added — build provenance attestations on releases
- `release.yml` now attests every released `.nupkg` with
  `actions/attest-build-provenance` (Sigstore). Verify with
  `gh attestation verify <file>.nupkg --owner systemslibrarian`.
  `KNOWN-GAPS.md` updated: author signing (Authenticode) remains the
  open gap; provenance no longer is.

## [1.0.1] — 2026-06-08

### Security — secrets removed from ACR build context
- `.dockerignore` now excludes `**/*.key`, `**/*.key.txt`, `**/Nuget*.key*`,
  `**/Marketplace*.key*`, `**/*.pfx`, `**/*.snk`, `**/*.pem`, and
  `**/secrets.json` — recursively. Pre-fix, the locally-stored
  `Nuget.key.txt` and `Marketplace.key.txt` were being uploaded into every
  ACR build-context archive on `pqhybriddemoacr` (they never made it into
  any running container image, but they were retained in ACR's
  build-archive storage). Keys have been rotated; nuget.org and VS
  Marketplace listings audited (only the legitimate `v1.0.0` and
  `v1.1.0` publishes from 2026-06-07 present). `.dockerignore` was
  also tightened to drop other dead weight (`docs-site/`, `TestResults/`,
  other `samples/` subdirs, top-level markdown / slnx that the
  Dockerfile does not COPY).

### Changed — NuGet release pipeline uses Trusted Publishing
- `.github/workflows/release.yml` now publishes to nuget.org via
  **Trusted Publishing** (OIDC) using `NuGet/login@v1`. The
  long-lived `NUGET_API_KEY` secret can be retired once a release
  has succeeded under the new flow. Setup runbook:
  [`docs/TRUSTED-PUBLISHING.md`](docs/TRUSTED-PUBLISHING.md). The
  job runs under a new `nuget` GitHub Environment so additional
  protection rules (required reviewers, restricted branches / tags)
  can be added without touching workflow code.
- `docs/RELEASE.md` updated to point at the new publish path.

### Added — WebApiDemo gold-standard playground (Phase 6: deploy + verify)
- Rolled `pqhybrid-webapidemo` Azure Container App to revision
  `--phase5` (image `pqhybriddemoacr.azurecr.io/pqhybrid-webapidemo:phase5`).
- Verified end-to-end on
  `https://demo.pqhybrid.systemslibrarian.dev/`: all section markers
  (hero, Why hybrid, demo tabs, rotation, all five PQH analyzer cards,
  code snippets, install matrix) render in a 32 KB single page; the
  `/api/backend` endpoint reports `native .NET 10 (...MLKem)` on Azure
  Linux 3.0 (OpenSSL 3.6.2 exercises the native ML-KEM / ML-DSA path);
  `/_blazor/negotiate` returns 200 with a `connectionToken` so the
  interactive components will wire up; `/swagger` still serves the
  REST surface.
- Caught and fixed mid-deploy: the `samples/WebApiDemo/Dockerfile`
  COPY block did not include `src/PostQuantum.Hybrid.Envelopes/`,
  which the Phase 1 csproj newly references. Local `dotnet build`
  succeeded because the full source tree is on disk; only the
  containerized build saw the omission (CS0234 from ACR run `ca3`).
  Followup: any new sample-only ProjectReference into another src/
  project needs a matching `COPY` in the Dockerfile.

### Added — WebApiDemo gold-standard playground (Phase 5: code samples + install)
- `Components/CopyableCode.razor` — reusable snippet card with a
  one-click copy button. Static JS handler in `App.razor` calls
  `navigator.clipboard.writeText`; works regardless of Blazor render
  mode, with an `execCommand("copy")` fallback for older browsers.
  "Copy" → "Copied" → "Copy" feedback with brief green tint.
- `#copy` section ships three production-shape snippets, each copyable:
  anonymous `HybridEnvelope.Seal / Open`; signed
  `SignedHybridEnvelope.Seal / Open` (with the verify-before-decapsulate
  note); and the ASP.NET Core wiring with `AddPostQuantumHybrid` +
  the `AddRotatingHybridKemKeys` alternative. Each block links back to
  the corresponding canonical sample under `samples/`.
- `#install` section: copyable `dotnet add package` block (base,
  Envelopes, Analyzers, AspNetCore), copyable `dotnet new` template
  block (`pqhybrid-app` / `pqhybrid-webapi` / `pqhybrid-envelope`),
  and a six-row "Which package do I want?" matrix that explicitly
  flags `Envelopes` as the default for new code and `Analyzers` as
  "always install."
- CSS additions: `.snippet` with dark header bar + label + copy
  button, `.copy-btn-done` flash state, `.package-matrix` two-column
  responsive grid. All vanilla CSS.

### Added — WebApiDemo gold-standard playground (Phase 4: analyzer demo)
- `Services/AnalyzerCatalog.cs` — static catalog of PQH001-PQH005 with
  each rule's `DiagnosticDescriptor.Title` and `MessageFormat` text
  quoted verbatim from the analyzer source, plus a hand-curated
  bad/good code pair for every rule. Centralized so the Razor view is
  data-driven.
- `Components/Hygiene.razor` renders one card per rule into the
  `#hygiene` section: rule chip, title, severity, short explanation,
  bad / good side-by-side code panes (red / green left borders),
  verbatim diagnostic text in an amber callout, link to the analyzer
  source on GitHub. The "good" snippets match the canonical patterns
  the codebase already enforces via the analyzer + `TreatWarningsAsErrors`
  on every project — so any drift from analyzer-clean code fails the
  build, which keeps the catalog honest.
- Trade-off noted in `Hygiene.razor`'s header: we do NOT run Roslyn at
  runtime (Microsoft.CodeAnalysis.CSharp would add ~3 MB to the image
  plus a one-shot ~1 s warm-up, and lock the demo to an exact analyzer
  PackageReference version). The catalog approach trades that for
  verbatim quotes from the analyzer source.
- CSS additions: `.hygiene-grid`, `.hygiene-card`, `.rule-chip`,
  `.rule-severity`, `.rule-grid` (responsive two-column at ≥720 px),
  `.rule-pane` with red/green variants, `.rule-diagnostic` amber
  callout. Plus accent-color helpers for code-block label text.

### Added — WebApiDemo gold-standard playground (Phase 3: key rotation)
- `Services/PlaygroundRotationService.cs` — in-process rotation service
  that mirrors the
  `PostQuantum.Hybrid.AspNetCore.IRotatingHybridKemKeyProvider` contract
  (`Version`, `PublicKey`, `PrivateKey`, `Rotated` event). The
  library's file-backed implementation is internal sealed; this
  in-process version sidesteps the file watcher (and the writable
  directory it would otherwise need in the container) while
  demonstrating the same contract. Atomic key swap under a lock,
  zeroizes the old pair's sensitive buffers on disposal.
- `Components/KeyRotation.razor` — visualization for the `#rotation`
  section. Big v@Version badge with a brief flash animation on
  rotation; "Rotate now" / "Seal probe" / "Try to open probe" workflow
  surfaces the educational payoff (envelopes sealed under vN do **not**
  open under vN+1 — fail-closed via ML-KEM's FIPS-203 implicit
  rejection, with a production note pointing at the 410 Gone pattern
  in `samples/KeyRotationDemo`). Rotation log keeps the last six
  events visible. Subscribes to `Rotated` in `OnInitialized` and
  unsubscribes via `IDisposable` so external rotations would also
  trigger re-render.
- CSS additions: `.rotation-shell`, `.rotation-cards`, `.version-badge`
  with `@@keyframes badgePulse`, `.rotation-log`.

### Added — WebApiDemo gold-standard playground (Phase 2: live demo tabs)
- `Components/LiveDemo.razor` — three-tab interactive demo wired into the
  Home page's `#demo` section. **Recommended** (default) drives
  `HybridEnvelope.Seal / Open`; **Intermediate** drives
  `SignedHybridEnvelope.Seal / Open` (signature verified before open);
  **Advanced** walks the manual `HybridKem` + `HKDF` + `AesGcm` pipeline
  step by step with inline annotations for the PQH analyzer rules each
  step satisfies (PQH001 on the typed encapsulation result, PQH002 on the
  typed shared-secret wrapper, PQH005 on KEM ct as associated data).
- Realistic service-to-service JSON payload as the default input (no toy
  "hello" strings); receipts surface envelope size, the
  `HybridEnvelope.OverheadBytes` / `SignedHybridEnvelope.OverheadBytes`
  constants, the resolved backend, and round-trip match.
- Tamper panel below each tab: flips one byte in the last produced
  envelope and shows fail-closed rejection (`CryptographicException`
  with backend-specific message).
- `wwwroot/app.css` extended with a complete demo-shell stylesheet: tab
  bar, textarea, button variants (primary/ghost/warn), receipt panels
  with status-coded left borders, step-list cards, and the amber tamper
  panel. All vanilla CSS; no Tailwind / Bootstrap dependency added.

### Added — WebApiDemo gold-standard playground (Phase 1: foundation)
- `samples/WebApiDemo` migrates from Minimal API + Swagger-at-root to
  **Blazor Server** hosting an interactive single-page playground at
  the site root. Swagger moves to `/swagger`; the JSON endpoints
  (`/pub/*`, `/seal`, `/sign`) stay intact for curl users.
- New `BackendInfoService` captures `MLKem.IsSupported` /
  `MLDsa.IsSupported` at startup; the playground header renders a live
  badge ("native .NET 10" vs "BouncyCastle fallback") so visitors see
  which backend the running container resolved per ADR 0012. New
  `GET /api/backend` exposes the same info as JSON.
- `POST /seal` now uses the **recommended high-level API**
  (`HybridEnvelope.Seal`) instead of the hand-rolled HKDF + AES-GCM
  pipeline it shipped with. Response payload includes the envelope
  byte length and `HybridEnvelope.OverheadBytes` for transparency.
- New `PostQuantum.Hybrid.Envelopes` ProjectReference on the sample
  (library remains dependency-free).
- Phase 1 visible content: hero with anchor-link nav, "Why hybrid?"
  section explaining the X25519+ML-KEM-768 and Ed25519+ML-DSA-65
  constructions, placeholders for the live demo, key rotation,
  security hygiene, code-you-can-copy, and install sections (phases 2
  through 5).

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
