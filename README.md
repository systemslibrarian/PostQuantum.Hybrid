# PostQuantum.Hybrid

[![CI](https://github.com/systemslibrarian/PostQuantum.Hybrid/actions/workflows/ci.yml/badge.svg)](https://github.com/systemslibrarian/PostQuantum.Hybrid/actions/workflows/ci.yml)
[![CodeQL](https://github.com/systemslibrarian/PostQuantum.Hybrid/actions/workflows/codeql.yml/badge.svg)](https://github.com/systemslibrarian/PostQuantum.Hybrid/actions/workflows/codeql.yml)
[![NuGet](https://img.shields.io/nuget/v/PostQuantum.Hybrid.svg)](https://www.nuget.org/packages/PostQuantum.Hybrid/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

High-level **hybrid post-quantum cryptography** for .NET. Combines a battle-tested
classical primitive with a NIST-standardized post-quantum algorithm so your
shared secrets and signatures remain secure as long as **either** primitive
holds — defense in depth against both today's attackers and tomorrow's quantum
adversaries.

- **Targets:** .NET 8 and .NET 10
- **Backends:** native `System.Security.Cryptography.MLKem` / `MLDsa` on .NET 10;
  BouncyCastle on .NET 8. Wire-compatible across both.
- **Dependencies:** `BouncyCastle.Cryptography` only.

## Algorithms

| Use case | Default combination | Standards |
|---|---|---|
| Key encapsulation | **X25519 + ML-KEM-768** | RFC 7748 + FIPS 203 |
| Digital signatures | **Ed25519 + ML-DSA-65** | RFC 8032 + FIPS 204 |

## Packages

| Package | Purpose |
|---|---|
| [**`PostQuantum.Hybrid`**](src/PostQuantum.Hybrid) | The library. Hybrid KEM and hybrid signatures. |
| [**`PostQuantum.Hybrid.Analyzers`**](src/PostQuantum.Hybrid.Analyzers) | Roslyn analyzers that catch common misuse at build time. PQH001 flags undisposed sensitive types. |
| [**`PostQuantum.Hybrid.Templates`**](templates) | `dotnet new pqhybrid-app` template for new projects. |

## Install

```bash
dotnet add package PostQuantum.Hybrid
dotnet add package PostQuantum.Hybrid.Analyzers   # optional but recommended
```

Or start a new project from the template:

```bash
dotnet new install PostQuantum.Hybrid.Templates
dotnet new pqhybrid-app -n MyHybridApp
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

The [`samples/`](samples) folder has five focused console demos:

| Sample | What it shows |
|---|---|
| [`BasicDemo`](samples/BasicDemo) | The shortest possible KEM + signature round trip. |
| [`KemEncryption`](samples/KemEncryption) | KEM → HKDF → AES-GCM: the canonical real-world way to use a KEM. |
| [`SignedDocument`](samples/SignedDocument) | Detached document signature with publish/verify split. |
| [`KeyPersistence`](samples/KeyPersistence) | Save and load PEM keys with proper disposal. |
| [`SecureMessenger`](samples/SecureMessenger) | End-to-end signed-and-encrypted messaging (Alice → Bob). |

Run any sample with:

```bash
dotnet run --project samples/SecureMessenger --framework net10.0
```

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
  zeros its buffers on dispose. The `PQH001` analyzer in
  `PostQuantum.Hybrid.Analyzers` flags any local that misses `using`.
- **Signature randomization:** ML-DSA signing is randomized by default — two
  signatures over the same data will differ. This is expected.

Detailed security guidance:

- [`SECURITY.md`](SECURITY.md) — disclosure process + threat overview
- [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) — in-scope / out-of-scope
- [`HARDENING-CHECKLIST.md`](HARDENING-CHECKLIST.md) — production deployment checklist
- [`src/SECURE-USAGE.md`](src/SECURE-USAGE.md) — prescriptive patterns
- [`KNOWN-GAPS.md`](KNOWN-GAPS.md) — what v1 deliberately doesn't do

## Documentation

| Doc | Audience |
|---|---|
| [README.md](README.md) | Everyone — entry point |
| [docs/SPEC.md](docs/SPEC.md) | Implementers porting to another language |
| [docs/design.md](docs/design.md) | Reviewers, anyone asking "why these choices?" |
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | Security reviewers |
| [docs/adr/](docs/adr/) | Architecture decision records |
| [HARDENING-CHECKLIST.md](HARDENING-CHECKLIST.md) | Operators deploying to production |
| [SECURITY.md](SECURITY.md) | Vulnerability reporters |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contributors |
| [CLAUDE.md](CLAUDE.md) | AI coding assistants working in this repo |
| [src/LLM-USAGE.md](src/LLM-USAGE.md) | AI coding assistants generating user code |
| [src/SECURE-USAGE.md](src/SECURE-USAGE.md) | Developers writing application code |
| [KNOWN-GAPS.md](KNOWN-GAPS.md) | Anyone asking "does it do X?" |
| [CHANGELOG.md](CHANGELOG.md) | Version history |

## Repo layout

```
src/PostQuantum.Hybrid/             the library
src/PostQuantum.Hybrid.Analyzers/   Roslyn analyzers (PQH001)
tests/PostQuantum.Hybrid.Tests/     xUnit tests (run on net8.0 and net10.0)
tests/PostQuantum.Hybrid.Analyzers.Tests/  analyzer tests
fuzz/PostQuantum.Hybrid.Fuzz/       property-style fuzz tests
benchmarks/PostQuantum.Hybrid.Benchmarks/  BenchmarkDotNet suite
samples/                             5 focused console demos
templates/                           dotnet new template
docs/                                spec, design, ADRs, threat model
tools/                               repo maintenance scripts
.github/                             CI, CodeQL, release, dependabot
```

## Development

```bash
# Build everything
dotnet build PostQuantum.Hybrid.slnx

# Run all tests on all TFMs
dotnet test PostQuantum.Hybrid.slnx

# Run the "is everything green?" script
pwsh tools/run-all.ps1

# Run benchmarks (Release only)
dotnet run --project benchmarks/PostQuantum.Hybrid.Benchmarks --framework net10.0 --configuration Release
```

## License

MIT. See [LICENSE](LICENSE).

---

*To God be the glory — 1 Corinthians 10:31.*
