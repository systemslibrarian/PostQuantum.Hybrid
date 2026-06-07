# CLAUDE.md — PostQuantum.Hybrid

Conventions and guardrails for working in this repository. Read before making
changes.

## What this is

A high-level **hybrid post-quantum cryptography** library for .NET. Combines
classical primitives (X25519, Ed25519) with NIST-standardized post-quantum
primitives (ML-KEM-768, ML-DSA-65). Targets **.NET 8** and **.NET 10**: on
.NET 10 it uses the native `System.Security.Cryptography.MLKem` / `MLDsa`;
on .NET 8 it uses BouncyCastle for the post-quantum side. BouncyCastle is
also used on both targets for X25519/Ed25519 (the BCL does not expose them
publicly yet). **No other dependencies.**

## Engineering discipline

- **Honesty over polish.** If something is incomplete, unproven, or risky, say
  so — in code comments, `SECURITY.md`, `KNOWN-GAPS.md`, and the README. Never
  overstate what the cryptography provides.
- **Fail-closed, always.** Every validation/decapsulation/verification failure
  throws or returns `false`. No silent downgrade. No "best effort" path. ML-KEM
  uses FIPS-203 implicit rejection — that is *not* a silent failure, the
  combined hybrid secret will diverge and downstream AEAD will authentically
  reject.
- **Don't roll your own crypto.** Use the native BCL primitives where
  available; use BouncyCastle for the gaps (X25519, Ed25519, and the .NET 8
  ML-KEM/ML-DSA fallback). Any hand-written curve or field arithmetic is a
  hard no.
- **Native BCL first when it actually works.** Prefer
  `System.Security.Cryptography` when the runtime *and* the underlying OS
  expose the primitive. The backend abstractions in
  `src/PostQuantum.Hybrid/Internal/Ml{Kem,Dsa}Backend.cs` check
  `MLKem.IsSupported` / `MLDsa.IsSupported` at runtime on .NET 10 and
  transparently fall back to BouncyCastle when those are `false` (e.g.
  Ubuntu 24.04's OpenSSL 3.0 does not ship ML-KEM/ML-DSA). See
  [ADR 0012](docs/adr/0012-runtime-backend-fallback.md).
- **Keep the surface small.** No speculative features. One combination per
  family (`X25519MlKem768`, `Ed25519MlDsa65`) in v1. Add new combinations only
  when there is a concrete user need *and* a new algorithm-id byte.
- **Wire-format stability is sacred.** The byte layouts in `docs/SPEC.md` are
  the public contract. Any change requires a new algorithm-id so v1 blobs
  continue to parse.

## Code conventions

- **Targets:** `net8.0;net10.0`. Code that calls native PQ APIs must be inside
  `#if NET10_0_OR_GREATER`. Code that uses HKDF / `CryptographicOperations` /
  `AesGcm` is fine on both — those have been in the BCL since .NET 6+.
- **Nullable** and **implicit usings** are on. `LangVersion` is `latest`.
- **Warnings as errors:** `TreatWarningsAsErrors=true`. Don't suppress an
  analyzer warning without a comment explaining why.
- **Documentation:** XML doc comments on every public member.
  `GenerateDocumentationFile=true`. Public-API surface changes update README
  and `CHANGELOG.md` in the same PR.
- **Naming:** `Hybrid*` for the public surface (e.g. `HybridKem`,
  `HybridKemKeyPair`); internal implementation lives in
  `PostQuantum.Hybrid.Internal`.
- **Secrets:** zero key material with `CryptographicOperations.ZeroMemory`
  after use. Every type that holds a private key implements `IDisposable`
  and zeros on dispose.
- **Determinism:** randomization comes only from
  `RandomNumberGenerator` / BouncyCastle's `SecureRandom`. Do not seed any RNG
  manually.

## Layout

```
src/PostQuantum.Hybrid/         library
  HybridKem.cs                  hybrid KEM (X25519 + ML-KEM-768)
  HybridSignature.cs            hybrid signatures (Ed25519 + ML-DSA-65)
  HybridKem*.cs                 key/keypair/ciphertext/result types
  HybridSignature*.cs           key/keypair types
  Internal/
    AlgorithmSizes.cs           wire-format byte constants
    KemCombiner.cs              HKDF-SHA256 combiner with transcript binding
    MlKemBackend.cs             native .NET 10 ML-KEM / BC .NET 8
    MlDsaBackend.cs             native .NET 10 ML-DSA / BC .NET 8
    PemFormatter.cs             PEM encode/decode
tests/PostQuantum.Hybrid.Tests/ xUnit, runs on both TFMs
samples/                        BasicDemo, KemEncryption, SignedDocument,
                                KeyPersistence, SecureMessenger
benchmarks/                     BenchmarkDotNet
docs/                           SPEC.md, design.md, THREAT-MODEL.md, adr/
.github/                        CI, CodeQL, templates
```

## Build & test

```bash
dotnet build PostQuantum.Hybrid.slnx
dotnet test  PostQuantum.Hybrid.slnx
```

**Both target frameworks must pass.** Tests run on `net8.0` (BouncyCastle
backend for ML-KEM/ML-DSA) and `net10.0` (native backend). A change is not
done until both pass.

To run a single sample:

```bash
dotnet run --project samples/SecureMessenger --framework net10.0
```

## Tests must stay honest

- A test that can't run its crypto should **skip with a reason**, never
  silently pass.
- Keep the fail-closed tests: tampered ciphertext, tampered signature,
  wrong key, wrong algorithm-id, wrong length, double-dispose.
- When adding a new algorithm combination, the test matrix must cover:
  generate → serialize → import → use → verify, *and* every cross-version
  serialization path (raw ↔ PEM, both backends if multi-targeted).

## Security-review rules

When asked to review or generate code that uses PostQuantum.Hybrid, apply
these rules:

- **Don't claim PQ security from a non-hybrid construction.** If the code
  uses only X25519 or only Ed25519, that's classical-only security. Flag it.
- **Never use a KEM shared secret as plaintext or as a MAC key directly.**
  Always feed it through HKDF/AEAD. The shared secret is a *seed*, not
  ciphertext.
- **Bind the KEM ciphertext into any AEAD derived from it.** Pass it as
  `associatedData` (see `samples/SecureMessenger`) so a swapped ciphertext
  causes authenticated decryption to fail.
- **Verify before decrypting in sign-then-encrypt flows.** When a packet
  carries both a hybrid signature and a hybrid KEM ciphertext, run
  `HybridSignature.Verify` *before* `HybridKem.Decapsulate`. Don't decrypt
  unauthenticated material.
- **Check the algorithm-id byte first.** The library does this for you on
  import; if your code parses a hybrid blob manually for any reason, replicate
  the check.
- **Dispose private keys.** Every code path that allocates a
  `HybridKemKeyPair` / `HybridSignatureKeyPair` / `HybridKemPrivateKey` /
  `HybridSignaturePrivateKey` / `HybridKemEncapsulationResult` must dispose
  it.
- **No hallucinations.** Base findings on code that is actually present.
  Cite file + line for every PASS/FAIL.

## Working in this repo

- Commit and push at natural checkpoints (after each substantial feature, doc
  block, or test suite). Don't sit on a giant unpushed working tree.
- Update `CHANGELOG.md` under **Unreleased** in every functional PR.
- For non-trivial design choices, write an ADR under `docs/adr/`.
- Run `dotnet build` and `dotnet test` before pushing; CI will catch the rest.

## Faith statement

This project is built in gratitude to God.

> *To God be the glory — 1 Corinthians 10:31.*
