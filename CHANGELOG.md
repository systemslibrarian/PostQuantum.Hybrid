# Changelog

All notable changes to **PostQuantum.Hybrid** will be documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] — Unreleased

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
