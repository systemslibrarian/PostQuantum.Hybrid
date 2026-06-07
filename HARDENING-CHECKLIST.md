# Hardening Checklist

A practical, opinionated checklist for deploying applications that use
PostQuantum.Hybrid in production. Tick each box before you ship.

## Key management

- [ ] **Private keys are never logged.** Search your code for any log/trace/
      telemetry path that touches a `HybridKemPrivateKey` /
      `HybridSignaturePrivateKey` instance, including its `.Export()` /
      `.ExportPem()` output. None should exist.
- [ ] **Private keys are never serialized into application telemetry,
      crash dumps, or error responses.**
- [ ] **Private keys are stored encrypted at rest** (KMS, HSM, sealed-box
      file, OS keystore) — not as plaintext `.pem` files in a repo or
      container image.
- [ ] **Private keys have a defined rotation cadence** (recommended:
      1–2 years for long-lived static keys; per-session for ephemeral keys).
- [ ] **Every code path that allocates a private-key type disposes it.**
      Use `using` declarations or `try/finally`. Static analysis can help.
- [ ] **Backups of private-key material exist and have been test-restored.**
      Losing the only copy of a long-lived signing key is a separate disaster
      from leaking it.

## KEM usage

- [ ] **The KEM shared secret is never used directly as plaintext or as a
      raw MAC key.** Feed it through HKDF or AEAD.
- [ ] **An AEAD (AES-GCM, ChaCha20-Poly1305) wraps the message payload.**
      The KEM is for the key, not the message.
- [ ] **The KEM ciphertext is bound into the AEAD as `associatedData`.**
      See `samples/SecureMessenger` for the pattern.
- [ ] **A fresh KEM ciphertext (and therefore fresh AEAD key) is generated
      per message.** Do not reuse a single KEM exchange across many AEAD
      encryptions without a session-level KDF chain.
- [ ] **The 32-byte shared secret is zeroed after use** (`CryptographicOperations.ZeroMemory`).
      The library does this internally; if you propagate the secret out,
      manage it yourself.

## Signature usage

- [ ] **Signatures are verified in constant-time-safe code paths.** The
      library's `Verify` is constant-time at the cryptographic layer; just
      don't add early `return` based on partial signature inspection.
- [ ] **Verification runs BEFORE any other processing of the payload.**
      Never parse, deserialize, decrypt, or otherwise act on a signed
      payload until `HybridSignature.Verify` returns true.
- [ ] **Verification failures are logged at coarse granularity only.** Log
      "signature mismatch for key X" — not the signature bytes, not the
      payload, not the public key body.
- [ ] **Replay protection exists at the protocol layer** (nonce, timestamp,
      sequence number — whatever fits). The library does not provide it.

## Integrity of artifacts in transit/at rest

- [ ] **Stored hybrid blobs are length-validated on load.** The library
      length-checks on `Import`/`FromBytes`; if your code reads bytes from
      disk/network and only later passes them to `Import`, ensure the read
      itself bounds the size.
- [ ] **Algorithm-id is treated as part of the keyed material.** Don't
      strip the first byte for "compactness"; it's the only thing
      preventing cross-algorithm confusion.

## Dependency hygiene

- [ ] **`BouncyCastle.Cryptography` is pinned to a version
      `>= 2.6.2`.** Older versions had different PQ APIs and have known
      issues fixed in newer releases.
- [ ] **Dependabot / Renovate is monitoring the BouncyCastle version.**
- [ ] **CI runs `dotnet list package --vulnerable`** on every build.

## Runtime / platform

- [ ] **The .NET 10 runtime is installed where the application runs.**
      The `MLKem.IsSupported` probe will tell you at startup; surface this
      as a clean error rather than crashing on first KEM use.
- [ ] **On Linux, the OpenSSL stack is recent enough for native ML-KEM/ML-DSA
      to work.** OpenSSL 3.5+ is the rough cutoff (varies by .NET runtime
      build). The library falls back to BouncyCastle automatically on net8.0
      but **not** on net10.0 — there, missing native PQ throws
      `PlatformNotSupportedException`.
- [ ] **Process memory protection** (DEP, ASLR, swap-off for crypto pages
      where supported) follows your platform's general hardening guide.

## Operational

- [ ] **The application has a "PQ readiness" health check** that
      exercises `HybridKem.GenerateKeyPair()` and `HybridSignature.GenerateKeyPair()`
      at startup and reports failure clearly. A silent fallback to
      classical-only is unacceptable.
- [ ] **There is a documented incident-response procedure** for the case
      where one of the four primitives is broken. The mitigation is a new
      algorithm-id byte; have the rollout plan written down already.
- [ ] **Monitoring includes counters for** sign success/failure,
      verify success/failure, encap success/failure, decap success/failure
      — labeled by algorithm identifier.

## Documentation

- [ ] **The system's documentation states which algorithms are in use**
      (`X25519MlKem768` for KEM, `Ed25519MlDsa65` for signatures) so
      operators can answer "are you post-quantum yet?" in plain language.
- [ ] **The threat model the system inherits from PostQuantum.Hybrid**
      (`docs/THREAT-MODEL.md`) is referenced or restated in the
      system's own security documentation.
