# Practical Steps to a 10/10 Gold Standard (Pre-Audit)

To make `PostQuantum.Hybrid` an undisputed 10/10 without relying on a third-party security audit, we must mathematically and procedurally prove the library is robust, transparent, and hostile to misuse. 

As an AI, I can execute these practical, hands-on tasks for you right now:

## 1. Eradicate "Doc Drift" (The Transparency Baseline)
A gold-standard cryptography library cannot have docs that contradict the codebase. Currently, `KNOWN-GAPS.md` and `docs/design.md` list analyzers, fuzz testing, and templates as "missing" or "planned", even though they already exist in the repo.
* **What I can do:** Do a sweeping reconciliation of the README, `KNOWN-GAPS.md`, and `docs/design.md` so that the stated architecture perfectly aligns with the shipped reality. 

## 2. Compilers as Cryptographers (Analyzer Expansion)
The best way to prevent cryptography misuse is to break the build when a developer does it wrong. The `PostQuantum.Hybrid.Analyzers` package currently has `PQH001` (Dispose checking). We need to build the rest of the guardrails.
* **What I can do:** Write the Roslyn analyzers for:
  * `PQH002`: Flag any direct use of `.SharedSecret` that isn't immediately passed into an HKDF (preventing KEM secrets from being used as direct AES keys or plaintext).
  * `PQH003`: Detect "Decrypt-before-Verify". If a KEM decapsulation happens before a signature verification in the same block/method, throw a compiler warning.

## 3. Unarguable Assurance (Mutation Testing)
You can't prove to auditors (or users) that your suite catches side-channel or cryptographic failures without mutation testing. We need to prove that if a single byte in the HKDF combiner is flipped, or if a fail-closed guard is bypassed, a test turns red.
* **What I can do:** Generate a `stryker-config.json` tailored precisely for the PQ code paths, configure the thresholds, and provide the command-line integration to run it locally. This removes the guesswork from "are our tests actually honest?"

## 4. Port the "JWT-Tier" Educational Material
`PostQuantum.Jwt` is a 10/10 because it educates the user on *why* the rules exist (like the "Read This First" warning).
* **What I can do:** 
  * Write a `HARDENING-CHECKLIST.md` for this repo, giving operators a deploy-time checklist (e.g., KEM bounds checking, log-redaction of ciphertexts).
  * Write `docs/SUPPLY-CHAIN.md` to document your deterministic build, SBOM generation, and provenance tracking.
  * Rewrite this repository's `README.md` to directly feature the "What this protects against / What it explicitly doesn't" matrix right at the top.

## 5. Formalize the Key Envelopes in Samples
If people copy/paste from `samples/SecureMessenger`, that code becomes their production code. The KEM shared secret HKDF expansion and AAD-binding logic must be flawless in the sample.
* **What I can do:** Audit and harden all `samples/` projects to ensure they are reference-architecture grade. I can add the exact AEAD (AES-GCM) binding layout with proper nonces and zeroed memory so consumers get it right by default.

---

**Next Steps:**
If you agree with this trajectory, just tell me: *"Start with phase X"* or *"Do all of the above"*, and I will immediately begin writing the code, analyzer rules, and documentation updates.

---

## 6. The Perfect Developer Experience (DX): Frictionless & Foolproof
For a cryptography library to truly become the standard, it must anticipate how everyday programmers will try to use it—and ensure the "lazy" or "obvious" path is also the perfectly secure path. Programmers often struggle with KEMs because they give back a raw byte array (`SharedSecret`) rather than an encrypted payload.

Here are the concrete DX improvements, examples, and samples we should build to achieve that "perfect for programmers" goal:

### A. The "Opinionated Envelope" Companion Package
Programmers usually don't want to wire up `HKDF` and `AesGcm` manually. They just want to encrypt a string or a file for a specific public key. 
* **Idea:** Introduce a lightweight envelope (either as a sample or a `PostQuantum.Hybrid.Envelopes` package) that wraps the `HKDF` + `AesGcm` logic.
* **Example API:**
  ```csharp
  // What the programmer actually wants to write:
  byte[] encryptedEnvelope = HybridEnvelope.Encrypt(recipientPubKey, "My secret message"u8);
  
  // And the reverse:
  byte[] plaintext = HybridEnvelope.Decrypt(recipientPrivKey, encryptedEnvelope, senderPubKeyForVerify);
  ```
  This abstracts away the KEM context-binding, nonce generation, and AES-GCM tag verification, removing 90% of the misuse surface.

### B. High-Fidelity, Real-World Samples
The existing samples (`SecureMessenger`, `KeyPersistence`) are a good start, but programmers learn by copying reference architectures. We need to provide:
1. **The ASP.NET Core SignalR / WebSockets Sample:** Show how two endpoints negotiate a PQ-secure session key using a `HybridKem` exchange over an open WebSockets channel. 
2. **The Cloud Key Vault Sample:** Show how to construct a `HybridSignaturePrivateKey` securely from an Azure Key Vault or AWS KMS secret, ensuring it never touches the disk, and is disposed of properly via `IDisposable`.
3. **The "Large File" Chunked Encryption Sample:** A major point in `KNOWN-GAPS.md` is that we don't have streaming encryption. We should provide a sample showing how to use the KEM shared secret to initialize an AES-GCM stream (or chunked `MemoryMappedFile` encryption) for a 4GB file, safely.

### C. A Crystal-Clear, Typed Exception Taxonomy
When things fail (and they should fail-closed), standard `CryptographicException`s are highly frustrating to debug in production. 
* **Idea:** Implement a `PostQuantumHybridException` with a typed `.Reason` enum, mirroring the excellent DX from the `PostQuantum.Jwt` library.
* **Example:**
  ```csharp
  try {
      HybridSignature.Verify(pubKey, msg, sig);
  } catch (PostQuantumHybridException ex) when (ex.Reason == FailureReason.AlgorithmIdMismatch) {
      logger.LogWarning("Protocol version mismatch detected.");
  }
  ```
  Programmers love actionable errors. If they pass an X25519 KEM key into an Ed25519 Signature function, the error should say exactly that, rather than giving a cryptic binary parsing exception.

### D. Intelligent `ToString()` and Debugger Display
When a developer inspects a `HybridKemPublicKey` in the Visual Studio / VS Code debugger, they shouldn't just see `{byte[1217]}`. 
* **Idea:** Add `[DebuggerDisplay]` attributes to all key types so they show up safely and cleanly in the debugger. 
  * *Public Key:* `[DebuggerDisplay("X25519-MLKEM768 Public Key ({ExportPem().Substring(0, 20)}...)")]`
  * *Private Key:* `[DebuggerDisplay("X25519-MLKEM768 Private Key (REDACTED)")]` 
  This small touch vastly improves the debugging experience while ensuring private key material is never accidentally written to logs via `.ToString()`.

### E. Extension Methods for `Span` and `Memory`
Modern .NET programmers use `Span<T>` and `Memory<T>` to avoid allocations. 
* **Idea:** Ensure every cryptographic facade (e.g., `Encapsulate`, `Sign`, `Verify`) accepts and returns `ReadOnlySpan<byte>` where appropriate, rather than forcing array allocations. Provide an allocation-free pipeline for developers writing high-performance, GC-sensitive networking code.