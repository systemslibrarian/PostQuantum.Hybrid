# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 1.x | ✅ |

## Reporting a vulnerability

Please report suspected security issues privately to
**systemslibrarian@gmail.com**. Do **not** open a public GitHub issue for
vulnerability reports. A maintainer will respond within 72 hours and
coordinate a fix and disclosure timeline with you.

## Threat model

PostQuantum.Hybrid combines a classical primitive with a NIST-standardized
post-quantum primitive so that the construction remains secure as long as
**either** primitive is unbroken.

### What this library protects against

- **Quantum adversaries:** the ML-KEM-768 and ML-DSA-65 components remain
  secure against a sufficiently capable quantum computer (NIST Level 3).
- **Cryptanalytic breaks in either single primitive:** if ML-KEM is broken
  before quantum adversaries arrive, X25519 still protects the shared secret;
  if X25519 is broken first, ML-KEM still protects it. The same applies for
  Ed25519 / ML-DSA-65 in the signature construction.
- **Ciphertext malleability for the hybrid secret:** the KEM combiner binds
  both ciphertexts into HKDF's `info` parameter, so any tampering with either
  ciphertext component produces a different shared secret.
- **Signature forgery:** an attacker must forge **both** the Ed25519 signature
  and the ML-DSA-65 signature to forge a hybrid signature.

### What this library does NOT protect against

- **Compromise of the private key.** Once a private key leaks, all past and
  future ciphertexts/signatures under it are compromised. Use disposable
  storage (`using`) and never persist private keys to disk in plaintext in
  production.
- **Side-channel attacks on the host.** This library does not implement
  side-channel countermeasures beyond what the underlying primitives provide.
- **"Harvest now, decrypt later":** if your *classical-only* ciphertexts were
  captured before you migrated to the hybrid construction, they remain
  vulnerable to future quantum attacks. PostQuantum.Hybrid protects new
  exchanges; it cannot retroactively protect old ones.
- **Protocol-level attacks.** This library provides cryptographic primitives
  only. Replay protection, freshness, authentication binding, and key
  rotation must be handled by the calling protocol.

## Operational guidance

- **Always dispose** `HybridKemKeyPair`, `HybridKemPrivateKey`,
  `HybridSignatureKeyPair`, `HybridSignaturePrivateKey`, and
  `HybridKemEncapsulationResult` — they zero their buffers on dispose.
- **Treat shared secrets as keys.** A KEM shared secret should be fed into a
  symmetric construction (AES-GCM, ChaCha20-Poly1305) — never used directly
  as message contents.
- **Use fresh ephemeral keys** for each encapsulation. The library does this
  automatically inside `Encapsulate`.
- **Validate algorithm IDs** in deserialization — the library does this for
  you; rejected blobs throw `CryptographicException`.

## Cryptographic dependencies

| Component | .NET 10 source | .NET 8 source |
|---|---|---|
| X25519 | BouncyCastle | BouncyCastle |
| Ed25519 | BouncyCastle | BouncyCastle |
| ML-KEM-768 | `System.Security.Cryptography.MLKem` | BouncyCastle |
| ML-DSA-65 | `System.Security.Cryptography.MLDsa` | BouncyCastle |
| HKDF-SHA256 | `System.Security.Cryptography.HKDF` | `System.Security.Cryptography.HKDF` |
