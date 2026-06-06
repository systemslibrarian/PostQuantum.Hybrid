# Changelog

All notable changes to **PostQuantum.Hybrid** will be documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] — Unreleased

### Added
- Initial release.
- Hybrid KEM (`HybridKem`) combining **X25519 + ML-KEM-768** with an
  HKDF-SHA256 combiner that binds both ciphertexts into the derived secret.
- Hybrid digital signatures (`HybridSignature`) combining **Ed25519 + ML-DSA-65**
  with concatenated signatures requiring both schemes to verify.
- Versioned, fixed-size wire format for every artifact (algorithm-id byte +
  classical part + post-quantum part).
- Raw byte and PEM serialization for all public/private keys.
- `IDisposable` private-key and encapsulation-result types with explicit
  zeroization of sensitive buffers.
- Multi-targets `net8.0` and `net10.0`:
  - `net10.0`: uses native `System.Security.Cryptography.MLKem` / `MLDsa`.
  - `net8.0`: uses BouncyCastle's `MLKemKeyPairGenerator` / `MLDsaSigner`.
  - Wire format is identical across both backends.
- Sample console app demonstrating both hybrid KEM and hybrid signatures.
- 36 unit tests covering round-trip, tamper detection, algorithm-id checks,
  serialization, dispose semantics, and length validation — run on both
  target frameworks.

### Security
- ML-KEM implicit rejection: malformed ciphertexts yield a pseudorandom secret
  rather than throwing, so downstream decryption fails authentically.
- Empty-context FIPS-204 pure ML-DSA signing, matching `.NET` native defaults.
