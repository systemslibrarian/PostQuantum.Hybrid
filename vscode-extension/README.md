# PostQuantum.Hybrid — VS Code Snippets

[![Visual Studio Marketplace](https://img.shields.io/visual-studio-marketplace/v/systemslibrarian.postquantum-hybrid-snippets?style=flat-square)](https://marketplace.visualstudio.com/items?itemName=systemslibrarian.postquantum-hybrid-snippets) [![Installs](https://img.shields.io/visual-studio-marketplace/i/systemslibrarian.postquantum-hybrid-snippets?style=flat-square)](https://marketplace.visualstudio.com/items?itemName=systemslibrarian.postquantum-hybrid-snippets)

C# snippets for the [PostQuantum.Hybrid](https://github.com/systemslibrarian/PostQuantum.Hybrid) library — hybrid post-quantum cryptography (X25519 + ML-KEM-768 for KEM, Ed25519 + ML-DSA-65 for signatures) on .NET 8 and .NET 10.

Every snippet follows the secure patterns the **PQH001 – PQH005** Roslyn analyzers (shipped in `PostQuantum.Hybrid.Analyzers`) enforce — so the generated code is analyzer-clean and secure by default.

This version focuses on the repo's safest default surfaces first: `Envelopes` for application code, `AspNetCore` DI/rotation for services, and readiness-friendly patterns for production hardening.

## Features

Provides IntelliSense snippets for C# files to accelerate working with the PostQuantum.Hybrid cryptography library.

Recommended starting points:

- `pqh-envelope` for anonymous seal/open flows.
- `pqh-envelope-signed` for authenticated confidentiality.
- `pqh-aspnet-config` for production-style ASP.NET Core registration.
- `pqh-aspnet-rotate` when you need zero-downtime KEM key rotation.

| Prefix | What it expands to |
|---|---|
| `pqh-envelope` | Recommended start for most applications: `HybridEnvelope.Seal` / `Open`. |
| `pqh-envelope-signed` | Recommended authenticated confidentiality pattern: `SignedHybridEnvelope.Seal` / `Open`. |
| `pqh-kem` | Hybrid KEM round-trip: generate → encapsulate → decapsulate, with `using` on every disposable. |
| `pqh-sig` | Hybrid signature round-trip: generate → sign → verify, with the result branched on (PQH004). |
| `pqh-kem-encrypt` | KEM → HKDF.Expand → AES-GCM. Uses `encapsulation.Secret` (the typed `HybridSharedSecret` wrapper), binds the KEM ciphertext into `associatedData` (PQH005), and zeroes the derived AES key. |
| `pqh-kem-decrypt` | Counterpart that uses `TryDecapsulate` at the trust boundary. |
| `pqh-signed-encrypted` | Sign-then-encrypt receiver pattern with verify-before-decrypt ordering (PQH003). |
| `pqh-key-load` | `TryImportPem` for both public and private keys, with caller-owned disposal. |
| `pqh-key-save` | Generate a fresh hybrid pair and persist as PEM, with Unix file-permission tightening. |
| `pqh-hkdf` | `HKDF.Expand` from a `HybridSharedSecret` — the typed wrapper flows in via implicit `ReadOnlySpan<byte>` conversion. |
| `pqh-aspnet-di` | `AddPostQuantumHybrid` registration with the bootstrap-pair-disposed-correctly pattern for demos/tests. |
| `pqh-aspnet-config` | `AddPostQuantumHybrid` using a configuration section. |
| `pqh-aspnet-rotate` | `AddRotatingHybridKemKeys` registration for zero-downtime KEM key rotation. |
| `pqh-readiness-check` | Startup smoke test that exercises a real signed-envelope seal/open flow. |

## Why These Snippets First?

- **Envelope snippets are the safest default.** They collapse KEM + HKDF + AEAD into one misuse-resistant API.
- **ASP.NET snippets reflect real deployment patterns.** Configuration-based registration and rotating KEM keys are more useful to service authors than only demo-style inline PEM wiring.
- **Readiness matters in production.** A snippet that exercises real crypto at startup is far more useful than a static support probe.

## Requirements

The snippets emit code that depends on the NuGet packages — install them in your project or they will not compile:

```bash
dotnet add package PostQuantum.Hybrid
dotnet add package PostQuantum.Hybrid.Analyzers      # strongly recommended
dotnet add package PostQuantum.Hybrid.Envelopes      # for Seal/Open helpers
dotnet add package PostQuantum.Hybrid.AspNetCore     # for the ASP.NET Core wiring
```

## Known Issues

See the main repository's [KNOWN-GAPS.md](https://github.com/systemslibrarian/PostQuantum.Hybrid/blob/main/KNOWN-GAPS.md) for current library limitations.

## Release Notes

See [CHANGELOG.md](CHANGELOG.md) for detailed release notes.

### 1.1.0
- Added `Envelopes`, ASP.NET Core configuration/rotation, and readiness-check snippets.
- Repositioned the snippet set around the safest high-level APIs first.
- Tightened packaging/docs consistency for Marketplace publishing.

### 1.0.1
- Marketplace polish release with icon, listing metadata, and packaging updates.

### 1.0.0
- Initial release of C# snippets for `PostQuantum.Hybrid`.

---

*To God be the glory — 1 Corinthians 10:31.*
