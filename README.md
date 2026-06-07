# PostQuantum.Hybrid

[![CI](https://github.com/systemslibrarian/PostQuantum.Hybrid/actions/workflows/ci.yml/badge.svg)](https://github.com/systemslibrarian/PostQuantum.Hybrid/actions/workflows/ci.yml)
[![CodeQL](https://github.com/systemslibrarian/PostQuantum.Hybrid/actions/workflows/codeql.yml/badge.svg)](https://github.com/systemslibrarian/PostQuantum.Hybrid/actions/workflows/codeql.yml)
[![codecov](https://codecov.io/gh/systemslibrarian/PostQuantum.Hybrid/branch/main/graph/badge.svg)](https://codecov.io/gh/systemslibrarian/PostQuantum.Hybrid)
[![Docs](https://img.shields.io/badge/docs-systemslibrarian.github.io-blue)](https://systemslibrarian.github.io/PostQuantum.Hybrid/)
[![NuGet](https://img.shields.io/nuget/v/PostQuantum.Hybrid.svg)](https://www.nuget.org/packages/PostQuantum.Hybrid/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

High-level **hybrid post-quantum cryptography** for .NET. Combines a battle-tested
classical primitive with a NIST-standardized post-quantum algorithm so your
shared secrets and signatures remain secure as long as **either** primitive
holds — defense in depth against both today's attackers and tomorrow's quantum
adversaries.

For .NET developers who need quantum-resistant key exchange and signatures
without becoming cryptography experts.

- **Targets:** .NET 8 and .NET 10
- **Backends:** native `System.Security.Cryptography.MLKem` / `MLDsa` on .NET 10;
  BouncyCastle on .NET 8. Wire-compatible across both.
- **Dependencies:** `BouncyCastle.Cryptography` only.

## Why PostQuantum.Hybrid?

- **Safe by default.** Every private-key and encapsulation type is
  `IDisposable` and zeros its buffers on dispose. Roslyn analyzers
  **PQH001–PQH005** catch the common misuses — undisposed sensitive
  types, raw shared secrets used as keys, decapsulating before verifying,
  ignored `Verify` results, AEAD without KEM-ciphertext binding — at
  build time, with code-fixes for the mechanical ones.
- **Honest about limits.** [`KNOWN-GAPS.md`](KNOWN-GAPS.md),
  [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md), and
  [`docs/adr/`](docs/adr/) state exactly what the library does, does
  not do, and why.
- **Versioned wire format.** Algorithm-id byte + fixed sizes means new
  combinations can be added later without breaking existing artifacts
  (see [`docs/SPEC.md`](docs/SPEC.md)).
- **Same blob on .NET 8 and .NET 10.** Native BCL primitives on .NET 10,
  BouncyCastle fallback on .NET 8 — wire-compatible either direction.
- **One library, one ecosystem.** `Envelopes` for `Seal`/`Open`,
  `AspNetCore` for DI + key rotation + `IDataProtector`, `TestingSupport`
  for downstream test suites, `Templates` for `dotnet new` scaffolds,
  a [VS Code snippets extension](vscode-extension/) for analyzer-clean
  starter code, and a [downstream hardening audit script](scripts/audit-pqh.ps1)
  that scans consumer `.csproj` files for missing best-practice
  references.

## Algorithms

| Use case | Default combination | Standards |
|---|---|---|
| Key encapsulation | **X25519 + ML-KEM-768** | RFC 7748 + FIPS 203 |
| Digital signatures | **Ed25519 + ML-DSA-65** | RFC 8032 + FIPS 204 |

## Packages

| Package | Purpose |
|---|---|
| [**`PostQuantum.Hybrid`**](src/PostQuantum.Hybrid) | The library. Hybrid KEM and hybrid signatures. |
| [**`PostQuantum.Hybrid.Envelopes`**](src/PostQuantum.Hybrid.Envelopes) | Opinionated `Seal`/`Open` wrappers combining KEM + HKDF + AES-GCM in one call. Anonymous and signed variants. |
| [**`PostQuantum.Hybrid.AspNetCore`**](src/PostQuantum.Hybrid.AspNetCore) | DI extensions: `AddPostQuantumHybrid(...)`, rotating key providers (`AddRotatingHybridKemKeys(...)`). |
| [**`PostQuantum.Hybrid.Analyzers`**](src/PostQuantum.Hybrid.Analyzers) | Roslyn analyzers **PQH001–PQH005** + code-fix providers that catch common misuse at build time. |
| [**`PostQuantum.Hybrid.TestingSupport`**](src/PostQuantum.Hybrid.TestingSupport) | Cached test keys, tamper-injection helpers, fake key providers for consumers' test suites. |
| [**`PostQuantum.Hybrid.Templates`**](templates) | `dotnet new pqhybrid-app` / `pqhybrid-webapi` / `pqhybrid-envelope` scaffolds. |

## Install

```bash
dotnet add package PostQuantum.Hybrid
dotnet add package PostQuantum.Hybrid.Analyzers      # strongly recommended — catches misuse at build time
dotnet add package PostQuantum.Hybrid.Envelopes      # if you want one-call seal/open
dotnet add package PostQuantum.Hybrid.AspNetCore     # if you're in ASP.NET Core
```

> **Install the analyzers.** `PostQuantum.Hybrid.Analyzers` is technically
> optional but turns five of the most-common cryptographic foot-guns into
> build-time errors. Skipping it is a hostile choice for your future self.

Or start a new project from a template:

```bash
dotnet new install PostQuantum.Hybrid.Templates

dotnet new pqhybrid-app      -n MyApp        # console KEM + signature demo
dotnet new pqhybrid-webapi   -n MyApi        # ASP.NET Core Minimal API starter
dotnet new pqhybrid-envelope -n MyEncryptor  # file-encryption CLI
```

## Quick start — Hybrid KEM

```csharp
using PostQuantum.Hybrid;

// Recipient: generate a key pair, publish the public key.
using var recipient = HybridKem.GenerateKeyPair();
byte[] publicKeyBytes = recipient.PublicKey.Export();

// Sender: encapsulate against the recipient's public key.
var publicKey = HybridKemPublicKey.Import(publicKeyBytes);
using var encapsulation = HybridKem.Encapsulate(publicKey);

byte[] ciphertext = encapsulation.Ciphertext.ToBytes();   // send to recipient
byte[] sharedSecret = encapsulation.SharedSecret;          // use locally (32 bytes)

// Recipient: decapsulate to recover the same shared secret.
byte[] recoveredSecret = HybridKem.Decapsulate(recipient.PrivateKey, ciphertext);
// recoveredSecret == sharedSecret
```

## Quick start — Hybrid signatures

```csharp
using PostQuantum.Hybrid;

using var signer = HybridSignature.GenerateKeyPair();

byte[] message = "Hello, post-quantum world!"u8.ToArray();
byte[] signature = HybridSignature.Sign(signer.PrivateKey, message);

bool valid = HybridSignature.Verify(signer.PublicKey, message, signature);
```

## Samples

The [`samples/`](samples) folder has **nine** focused demos. See
[`samples/README.md`](samples/README.md) for the recommended reading
order.

| Sample | What it shows |
|---|---|
| [`BasicDemo`](samples/BasicDemo) | The shortest possible KEM + signature round trip. |
| ⭐ [`EnvelopesDemo`](samples/EnvelopesDemo) | **Recommended starting point.** One-call `HybridEnvelope.Seal`/`Open` and `SignedHybridEnvelope.Seal`/`Open` — replaces the whole KEM → HKDF → AES-GCM pipeline. |
| [`KemEncryption`](samples/KemEncryption) | The same encryption flow wired by hand — see what `Envelopes` does for you. |
| [`SignedDocument`](samples/SignedDocument) | Detached document signature with publish/verify split. |
| [`KeyPersistence`](samples/KeyPersistence) | Save and load PEM keys with `TryImportPem` at the trust boundary. |
| [`SecureMessenger`](samples/SecureMessenger) | End-to-end signed-and-encrypted messaging (Alice → Bob). |
| [`LargeFileEncryption`](samples/LargeFileEncryption) | Chunked AES-GCM encryption of multi-GB files with one hybrid KEM exchange. |
| [`WebApiDemo`](samples/WebApiDemo) | ASP.NET Core Minimal API exercising the `AspNetCore` package's DI. |
| [`KeyRotationDemo`](samples/KeyRotationDemo) | ASP.NET Core + `AddRotatingHybridKemKeys` + a sidecar that rewrites the on-disk PEM files every 15 s. Proves zero-downtime rotation. |

Run any sample with:

```bash
dotnet run --project samples/EnvelopesDemo --framework net10.0
```

To exercise every sample on every TFM and assert each one's happy
path, tamper detection, and analyzer-cleanness in one pass:

```pwsh
pwsh tools/run-all-samples.ps1
```

That script also runs the solution-wide build with
`TreatWarningsAsErrors=true` first, so any analyzer regression in a
sample fails the run before the samples even start.

## Serialization

Every key/ciphertext/signature is a versioned, fixed-size byte blob. Both raw
and PEM encodings are supported.

```csharp
// Raw bytes
byte[] pubBytes = signer.PublicKey.Export();
var pubFromBytes = HybridSignaturePublicKey.Import(pubBytes);

// PEM
string pubPem = signer.PublicKey.ExportPem();
var pubFromPem = HybridSignaturePublicKey.ImportPem(pubPem);
```

| Artifact | Size (bytes) | PEM label |
|---|---|---|
| Hybrid KEM public key | 1217 | `PQH HYBRID KEM PUBLIC KEY` |
| Hybrid KEM private key | 2433 | `PQH HYBRID KEM PRIVATE KEY` |
| Hybrid KEM ciphertext | 1121 | (raw only) |
| Hybrid signature public key | 1985 | `PQH HYBRID SIG PUBLIC KEY` |
| Hybrid signature private key | 4065 | `PQH HYBRID SIG PRIVATE KEY` |
| Hybrid signature | 3374 | (raw only) |
| Shared secret | 32 | (raw only) |

For the full normative wire-format spec, see [`docs/SPEC.md`](docs/SPEC.md).

### X.509 SPKI / PKCS#8 envelopes (preview)

For embedding hybrid keys inside an X.509 certificate template or a
PKCS#8-aware key store, the v1 wire format also rides inside a
standard DER envelope:

```csharp
byte[] spki  = signer.PublicKey.ExportSubjectPublicKeyInfo();
byte[] pkcs8 = signer.PrivateKey.ExportPkcs8PrivateKey();

var pubFromSpki  = HybridSignaturePublicKey.ImportSubjectPublicKeyInfo(spki);
using var privFromPkcs8 = HybridSignaturePrivateKey.ImportPkcs8PrivateKey(pkcs8);
```

The algorithm OIDs are **placeholders** under RFC 5612's IANA Example
PEN (`1.3.6.1.4.1.32473`) until the IETF LAMPS WG finalizes composite
OIDs. The framing is standard X.509 SPKI / PKCS#8 v1, so third-party
DER tooling parses the structure; only the OID lookup will need
updating when LAMPS ships. See
[ADR 0014](docs/adr/0014-spki-pkcs8-preview.md).

### Alternative combiner: X-Wing (preview)

Algorithm-id `0x02` swaps the v1 HKDF-SHA256 combiner for an X-Wing-style
SHA3-256 combiner (per
[draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/))
over the same component sizes:

```csharp
using var pair = HybridKem.GenerateKeyPair(HybridKemAlgorithm.X25519MlKem768XWing);
```

Opt-in only; `HybridKem.Default` stays on the v1 HKDF combiner. The
v1 component layout is preserved, so the resulting blobs are **not**
byte-compatible with the IETF X-Wing wire format (PQ-first ordering);
strict IETF interop is a future algorithm-id. See
[ADR 0013](docs/adr/0013-xwing-combiner-preview.md).

## Performance

Pinned baselines from a BenchmarkDotNet run on Windows 11 + Intel
Core Ultra 7 256V @ 2.20 GHz (see [`benchmarks/`](benchmarks)). The
weekly [`Benchmarks` workflow](.github/workflows/benchmark.yml)
re-runs these on every push to track regressions; the
[`tools/compare-benchmarks.ps1`](tools/compare-benchmarks.ps1) script
gates PRs at +25% over baseline.

**`.NET 10` (native `MLKem` / `MLDsa`):**

| Operation | Mean | Allocated |
|---|---:|---:|
| `HybridKem.GenerateKeyPair` | 277 µs | 6.3 KB |
| `HybridKem.Encapsulate` | 503 µs | 6.2 KB |
| `HybridKem.Decapsulate` | 322 µs | 3.1 KB |
| `HybridSignature.GenerateKeyPair` | 1.80 ms | 9.5 KB |
| `HybridSignature.Sign` (64 B msg) | 1.63 ms | 11.4 KB |
| `HybridSignature.Sign` (64 KB msg) | 3.23 ms | 139 KB |
| `HybridSignature.Verify` (64 B msg) | 583 µs | 7.1 KB |
| `HybridSignature.Verify` (64 KB msg) | 1.56 ms | 135 KB |

**`.NET 8` (BouncyCastle backend):**

| Operation | Mean | Allocated |
|---|---:|---:|
| `HybridKem.GenerateKeyPair` | 591 µs | 29 KB |
| `HybridKem.Encapsulate` | 978 µs | 36 KB |
| `HybridKem.Decapsulate` | 861 µs | 40 KB |
| `HybridSignature.Sign` (64 B msg) | 4.17 ms | 640 KB |
| `HybridSignature.Verify` (64 B msg) | 1.14 ms | 189 KB |

The native `net10.0` backend is roughly 2–3× faster and 10–60×
less allocation-heavy than the `net8.0` BouncyCastle fallback,
depending on the operation. Both wire-compatibly produce the same
1217 / 2433 / 1121 / 1985 / 4065 / 3374 byte artifacts.

## How it works

### Hybrid KEM combiner

The two component shared secrets are combined with HKDF-SHA256, with both
ciphertexts bound into the `info` parameter so the derived secret depends on
the full transcript:

```
sharedSecret = HKDF-SHA256(
    ikm  = ss_x25519 ‖ ss_mlkem,
    info = "PostQuantum.Hybrid v1 KEM X25519-MLKEM768" ‖ ct_x25519 ‖ ct_mlkem,
    len  = 32 )
```

See [ADR 0003](docs/adr/0003-kem-combiner.md) for rationale.

### Hybrid signature combiner

Both schemes independently sign the message bytes (each does its own internal
hashing). The signatures are concatenated; verification requires **both** to
verify. See [ADR 0004](docs/adr/0004-signature-concat.md).

## Security

- **Algorithm agility:** wire format begins with a 1-byte algorithm identifier
  so future combinations can be added without breaking existing artifacts.
- **Implicit rejection:** ML-KEM uses FIPS 203's implicit rejection — malformed
  ciphertexts yield pseudorandom secrets rather than throwing.
- **Sensitive material:** every private-key type implements `IDisposable` and
  zeros its buffers on dispose.
- **Build-time misuse checks:** `PostQuantum.Hybrid.Analyzers` ships five
  rules with code-fixes — **PQH001** (undisposed sensitive types),
  **PQH002** (raw `SharedSecret` used as a symmetric key without HKDF),
  **PQH003** (decapsulate before verify), **PQH004** (ignored
  `HybridSignature.Verify` result), and **PQH005** (AEAD without
  KEM-ciphertext binding as `associatedData`).
- **Signature randomization:** ML-DSA signing is randomized by default — two
  signatures over the same data will differ. This is expected.

Detailed security guidance:

- [`SECURITY.md`](SECURITY.md) — disclosure process + threat overview
- [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) — in-scope / out-of-scope
- [`HARDENING-CHECKLIST.md`](HARDENING-CHECKLIST.md) — production deployment checklist
- [`src/SECURE-USAGE.md`](src/SECURE-USAGE.md) — prescriptive patterns
- [`KNOWN-GAPS.md`](KNOWN-GAPS.md) — what v1 deliberately doesn't do

Consumer self-check:

```pwsh
pwsh scripts/audit-pqh.ps1 -Path path/to/your/solution
```

The audit script walks consumer `.csproj` files, flags projects that
reference `PostQuantum.Hybrid` without also referencing
`PostQuantum.Hybrid.Analyzers`, and prints a punch list. See
[`scripts/README.md`](scripts/README.md).

## Documentation

| Doc | Audience |
|---|---|
| [README.md](README.md) | Everyone — entry point |
| [DocFX site](https://systemslibrarian.github.io/PostQuantum.Hybrid/) | Browsable API reference + handwritten guides (auto-deploys on push to main) |
| [docs/SPEC.md](docs/SPEC.md) | Implementers porting to another language |
| [docs/design.md](docs/design.md) | Reviewers, anyone asking "why these choices?" |
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | Security reviewers |
| [docs/adr/](docs/adr/) | Architecture decision records (currently 14) |
| [HARDENING-CHECKLIST.md](HARDENING-CHECKLIST.md) | Operators deploying to production |
| [SECURITY.md](SECURITY.md) | Vulnerability reporters |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contributors |
| [CLAUDE.md](CLAUDE.md) | AI coding assistants working in this repo |
| [src/LLM-USAGE.md](src/LLM-USAGE.md) | AI coding assistants generating user code |
| [src/SECURE-USAGE.md](src/SECURE-USAGE.md) | Developers writing application code |
| [samples/README.md](samples/README.md) | Walking the 9 sample demos in order |
| [scripts/README.md](scripts/README.md) | Consumer audit script |
| [vscode-extension/README.md](vscode-extension/README.md) | VS Code snippets extension |
| [KNOWN-GAPS.md](KNOWN-GAPS.md) | Anyone asking "does it do X?" |
| [CHANGELOG.md](CHANGELOG.md) | Version history |

## Repo layout

```
src/PostQuantum.Hybrid/                       the library
src/PostQuantum.Hybrid.Envelopes/             Seal/Open opinionated wrappers
src/PostQuantum.Hybrid.AspNetCore/            DI + key rotation for ASP.NET Core
src/PostQuantum.Hybrid.Analyzers/             Roslyn analyzers + code-fixes (PQH001-005)
src/PostQuantum.Hybrid.TestingSupport/        test helpers for consumers
tests/PostQuantum.Hybrid.Tests/               xUnit tests (run on net8.0 and net10.0)
tests/PostQuantum.Hybrid.Envelopes.Tests/     Envelopes tests
tests/PostQuantum.Hybrid.AspNetCore.Tests/    DI + rotation tests
tests/PostQuantum.Hybrid.Analyzers.Tests/     analyzer tests
tests/PostQuantum.Hybrid.TestingSupport.Tests/ test-helpers tests
fuzz/PostQuantum.Hybrid.Fuzz/                 property-style fuzz tests
benchmarks/PostQuantum.Hybrid.Benchmarks/     BenchmarkDotNet suite
samples/                                      9 focused demos (BasicDemo .. KeyRotationDemo)
templates/                                    3 dotnet new templates
docs/                                         spec, design, ADRs (1-14), threat model, perf
docs-site/                                    DocFX config + landing pages (deploys to GH Pages)
scripts/                                      consumer preflight tools (see scripts/README.md)
tools/                                        repo maintenance scripts (incl. run-all-samples.ps1)
vscode-extension/                             PostQuantum.Hybrid Snippets (VS Code Marketplace)
.github/                                      CI, CodeQL, release, SBOM, mutation, bench, docs
```

## Development

```bash
# Build everything
dotnet build PostQuantum.Hybrid.slnx

# Run all tests on all TFMs (340+ tests across 5 suites)
dotnet test PostQuantum.Hybrid.slnx

# Run every sample on every TFM (18 runs) with stricter checks than the test
# suite alone — exit codes, expected output, stack-trace scanning, end-to-end
# HTTP for the web samples, SHA-256 diff for LargeFileEncryption, full
# zero-downtime rotation flow for KeyRotationDemo
pwsh tools/run-all-samples.ps1

# Run the broader "is everything green?" wrapper
pwsh tools/run-all.ps1

# Run benchmarks (Release only)
dotnet run --project benchmarks/PostQuantum.Hybrid.Benchmarks --framework net10.0 --configuration Release

# Build the DocFX site locally
docfx docs-site/docfx.json --serve
```

## License

MIT. See [LICENSE](LICENSE).

---

*To God be the glory — 1 Corinthians 10:31.*
