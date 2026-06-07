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

## v1.x preview opt-ins

- **X-Wing combiner at algorithm-id `0x02`** — pass
  `HybridKemAlgorithm.X25519MlKem768XWing` to `HybridKem.GenerateKeyPair`
  for the SHA3-based combiner from
  [draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/).
  See [ADR 0013](../docs/adr/0013-xwing-combiner-preview.md).
- **X.509 SPKI / PKCS#8 framing** — `ExportSubjectPublicKeyInfo`,
  `ExportPkcs8PrivateKey`, and the matching `Import*` methods on all
  four key types. Algorithm OIDs are RFC 5612 placeholders until
  the IETF LAMPS WG allocates final values. See
  [ADR 0014](../docs/adr/0014-spki-pkcs8-preview.md).

## Companion tools

- [VS Code Snippets extension](../vscode-extension/README.md) — nine
  analyzer-clean C# snippets covering the canonical patterns
  (Envelopes, sign-then-encrypt, PEM load/save, rotation wiring, …).
- [`tools/run-all-samples.ps1`](../tools/run-all-samples.ps1) — the
  gold-standard sample verification harness: per-sample timing,
  stack-trace scanning, SHA-256 round-trip checks, and the full
  zero-downtime rotation flow for `KeyRotationDemo`.
- [`scripts/audit-pqh.ps1`](../scripts/audit-pqh.ps1) — drop-in
  consumer hardening check; flags downstream projects that reference
  the library without also referencing `PostQuantum.Hybrid.Analyzers`.

## Next steps

- [Getting Started](getting-started.md)
- [Samples](../samples/README.md)
- [API Reference](api/)
- [SPEC](../docs/SPEC.md) and [Design Rationale](../docs/design.md)
- [Hardening Checklist](../HARDENING-CHECKLIST.md) — when you're ready to deploy.

---

*To God be the glory — 1 Corinthians 10:31.*
