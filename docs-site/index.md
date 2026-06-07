# PostQuantum.Hybrid

**High-level hybrid post-quantum cryptography for .NET 8 and .NET 10.**

Combines a battle-tested classical primitive with a NIST-standardized
post-quantum algorithm so your shared secrets and signatures remain
secure **as long as either primitive holds** — defense in depth
against both today's attackers and tomorrow's quantum adversaries.

| Use case | Default combination | Standards |
|---|---|---|
| Key encapsulation | **X25519 + ML-KEM-768** | RFC 7748 + FIPS 203 |
| Digital signatures | **Ed25519 + ML-DSA-65** | RFC 8032 + FIPS 204 |

## Why this library

- **Safe by default** — every private-key and encapsulation type is
  `IDisposable` and zeros its buffers on dispose. Roslyn analyzers
  **PQH001 – PQH005** catch common misuses (undisposed sensitive
  types, raw shared secrets used as keys, decapsulating before
  verifying, ignored `Verify` results, AEAD without KEM-ciphertext
  binding) at build time, with code-fixes for the mechanical ones.
- **Honest about limits** — [Known Gaps](../KNOWN-GAPS.md),
  [Threat Model](../docs/THREAT-MODEL.md), and the
  [ADRs](../docs/adr/) state exactly what the library does and does
  not do.
- **Versioned wire format** — algorithm-id byte + fixed sizes means
  new combinations can be added later without breaking existing
  artifacts. See the [SPEC](../docs/SPEC.md).
- **Same blob on .NET 8 and .NET 10** — native BCL primitives on
  .NET 10, BouncyCastle fallback on .NET 8 — wire-compatible either
  direction.

## Install

```bash
dotnet add package PostQuantum.Hybrid
dotnet add package PostQuantum.Hybrid.Analyzers      # strongly recommended
dotnet add package PostQuantum.Hybrid.Envelopes      # for one-call seal/open
dotnet add package PostQuantum.Hybrid.AspNetCore     # for the ASP.NET Core wiring
```

## Next steps

- [Getting Started](getting-started.md)
- [Samples](../samples/README.md)
- [API Reference](api/)
- [SPEC](../docs/SPEC.md) and [Design Rationale](../docs/design.md)

---

*To God be the glory — 1 Corinthians 10:31.*
