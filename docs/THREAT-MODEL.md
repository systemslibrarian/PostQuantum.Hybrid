# Threat Model

This document records the security assumptions, in-scope threats, and explicit
non-goals for **PostQuantum.Hybrid**.

## Assumptions

1. The host OS, .NET runtime, and `System.Security.Cryptography` (.NET 10) /
   `BouncyCastle.Cryptography` (.NET 8) packages are not compromised.
2. The system RNG (`System.Security.Cryptography.RandomNumberGenerator`, and
   BouncyCastle's `SecureRandom` which delegates to it on .NET) returns
   uniformly random bytes.
3. The caller's process does not leak private-key bytes through application
   logging, swap files, telemetry, or crash dumps.
4. The caller follows the library's `IDisposable` contract.

## Adversary model

We consider three adversaries:

### Classical adversary (today)

- Polynomial-time classical computation.
- Read/modify network traffic.
- May obtain ciphertexts and signatures freely.
- May obtain public keys freely.
- May NOT obtain private keys.

Our defense: standard cryptographic security of X25519 + ML-KEM-768 and
Ed25519 + ML-DSA-65. The hybrid construction here gives *at least* the
security of the stronger of the two primitives.

### Quantum adversary (future)

- Cryptographically-relevant quantum computer (CRQC).
- Same network capabilities as the classical adversary.
- May have **already captured** past ciphertexts ("harvest now, decrypt
  later").

Our defense: ML-KEM-768 and ML-DSA-65 are designed to resist quantum attack
at NIST Level 3 (~AES-192 equivalent). The classical components add no
security against this adversary, but they are kept for defense in depth
against the next bullet.

### Cryptanalytic-break adversary

- One of the four primitives is broken (e.g. a new attack reduces ML-KEM
  security below useful levels, or an X25519 implementation flaw is
  discovered).

Our defense: as long as **at least one** primitive in each family remains
unbroken, the construction is secure. This is the entire point of going
hybrid.

## In-scope threats (we protect against these)

- **Eavesdropping on KEM ciphertexts.** Recovering the shared secret
  requires breaking both X25519 and ML-KEM-768.
- **Tampering with KEM ciphertexts.** Either ciphertext component being
  altered produces a different combined secret on the receiver side, so any
  AEAD downstream fails to decrypt.
- **Signature forgery.** Forging a hybrid signature requires forging both
  Ed25519 and ML-DSA-65, which requires breaking the underlying primitive
  (or stealing the private key).
- **Cross-algorithm confusion.** The algorithm-id byte in every wire artifact
  is checked on import/verify so blobs of mismatched types cannot be confused.
- **Length confusion.** All wire artifacts have fixed sizes and are length-
  checked on import.
- **Implicit rejection on malformed KEM ciphertexts.** Per FIPS 203, ML-KEM
  Decapsulate never throws on a bad ciphertext — it returns a pseudorandom
  secret. The combined hybrid secret will then differ from the sender's, so
  authenticated decryption fails naturally.
- **Sensitive-data lingering in memory.** All private-key types implement
  `IDisposable` and zero their buffers on dispose.

## Out-of-scope threats (NOT protected against)

- **Private-key compromise.** If an attacker reads a private key out of
  process memory, a file, or a backup, all past and future ciphertexts
  and signatures under that key are compromised. The library cannot
  prevent this; use a KMS / HSM in high-stakes deployments.
- **Side-channel attacks.** The library does not implement constant-time
  comparisons or memory-access patterns beyond what the underlying
  primitives provide. Timing, cache, electromagnetic, and power analysis
  attacks are out of scope.
- **Harvest-now-decrypt-later on classical-only ciphertexts.** If you only
  *just now* migrated from classical-only cryptography to PostQuantum.Hybrid,
  ciphertexts captured before the migration remain vulnerable to future
  quantum attack. The library cannot help you retroactively.
- **Protocol-level attacks.** Replay, freshness, identity binding, key
  rotation, transcript binding across multiple messages — all are the
  responsibility of the calling protocol. The library provides primitives,
  not protocols.
- **Compromised RNG.** Generating keys with a broken RNG yields broken
  keys. We have no defense against this at the library layer.
- **Supply-chain compromise of dependencies.** Mitigated via NuGet
  package signing and (planned) reproducible builds; not eliminated.

## Operational guidance

These are not threats so much as recommended postures:

- **Rotate keys.** A 1- to 2-year rotation cadence limits the blast radius
  of an undetected key compromise. KEM ephemeral keys are already rotated
  per-encapsulation; long-lived static keys are the concern.
- **Bind context.** When you derive symmetric keys from a KEM shared secret,
  use HKDF with a context-specific `info` parameter (see
  `samples/SecureMessenger`) so the same KEM exchange can't be replayed
  in a different application context.
- **Always include AEAD over the message.** Never use a KEM shared secret
  directly as plaintext or as a MAC key without an AEAD construction
  (AES-GCM, ChaCha20-Poly1305).
- **Verify before decrypting.** When combining sign-then-encrypt, verify
  the signature **before** running KEM decapsulation. See
  `samples/SecureMessenger` for the canonical layout.

## What we will do on a vulnerability disclosure

See [SECURITY.md](../SECURITY.md) for the disclosure process.

If a vulnerability is found that breaks one of the four primitives:

1. We release a patch version with new algorithm identifiers that opt into
   a stronger combination (e.g. `X25519MlKem1024` or a different PQ KEM).
2. The old algorithm identifier remains *parseable* (so existing keys still
   work) but is marked deprecated.
3. A migration tool helps callers re-encrypt or re-sign their stored data
   under the new identifier.
