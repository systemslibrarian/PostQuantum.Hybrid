# Changelog

## 1.1.0

### Added
- Recommended high-level snippets for `PostQuantum.Hybrid.Envelopes`:
  `pqh-envelope` and `pqh-envelope-signed`.
- ASP.NET Core service snippets for configuration-based registration and
  zero-downtime KEM key rotation: `pqh-aspnet-config` and
  `pqh-aspnet-rotate`.
- `pqh-readiness-check` to exercise a real signed-envelope crypto path at
  startup.

### Changed
- Reframed the extension around the safest default surfaces first:
  Envelopes for application code, AspNetCore registration for services,
  and readiness-friendly operational patterns.
- Tightened Marketplace packaging by excluding `.vsix` payloads from the
  extension bundle.
- Refreshed README/release notes to match the actual snippet set.

## 1.0.1

### Changed
- Marketplace polish release with icon, listing metadata, and packaging
  improvements.

## 1.0.0

### Added
- C# snippets for the canonical PostQuantum.Hybrid usage patterns:
  `pqh-kem`, `pqh-sig`, `pqh-kem-encrypt`, `pqh-kem-decrypt`,
  `pqh-signed-encrypted`, `pqh-key-load`, `pqh-key-save`, `pqh-hkdf`,
  `pqh-aspnet-di`.
- Every snippet body follows the patterns enforced by the
  `PostQuantum.Hybrid.Analyzers` package (PQH001 – PQH005), so the
  generated code is analyzer-clean by default.
