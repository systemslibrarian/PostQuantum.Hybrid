# ADR 0006: Backend abstraction for ML-KEM and ML-DSA

**Status:** Accepted

## Context

Per [ADR 0005](0005-multi-target-net8-net10.md) the library multi-targets
net8.0 and net10.0 with different backends per TFM. We need an internal
seam so the public API code never depends directly on either backend.

## Options considered

### A. `#if` blocks scattered throughout `HybridKem.cs` / `HybridSignature.cs`

Easy to start. Becomes unreadable as soon as we add a second variant.

### B. A backend abstraction with conditional implementation

A small internal interface or static class with one method per operation.
Implementations chosen at compile time with `#if NET10_0_OR_GREATER`.

### C. A runtime-selected interface with `MLKem.IsSupported`-style probes

Most flexible but mixes runtime branching with compile-time abstraction;
overkill for our needs.

## Decision

Option **B**: two internal static classes,
`PostQuantum.Hybrid.Internal.MlKemBackend` and
`PostQuantum.Hybrid.Internal.MlDsaBackend`, each with a single set of
method signatures and a `#if NET10_0_OR_GREATER` / `#else` body.

```csharp
internal static class MlKemBackend
{
    public static bool IsSupported { get; }
    public static (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPair();
    public static void Encapsulate(ReadOnlySpan<byte> publicKey,
                                   Span<byte> ciphertext,
                                   Span<byte> sharedSecret);
    public static void Decapsulate(ReadOnlySpan<byte> privateKey,
                                   ReadOnlySpan<byte> ciphertext,
                                   Span<byte> sharedSecret);
}
```

## Rationale

- **One file per backend per primitive.** Easy to read, easy to audit.
- **Compile-time selection means zero runtime cost.** The non-target
  backend is never even compiled into the produced DLL for that TFM.
- **No interface allocation.** Static methods, span-based signatures.
- **`IsSupported` exposes the native `MLKem.IsSupported` probe.** On older
  platforms where .NET 10 is installed but the OS-level crypto stack is
  too old (e.g. OpenSSL < 3.5 on some Linux distros), the library throws
  `PlatformNotSupportedException` with a clear message rather than crashing
  inside an `MLKem.GenerateKey` call.

## Consequences

- All public-facing types (`HybridKem`, `HybridSignature`) call the backend
  abstractions; the public API has zero `#if` blocks.
- Adding a future post-quantum primitive (SLH-DSA?) follows the same
  pattern: one new `*Backend.cs` file per primitive.
- The X25519 and Ed25519 calls are *not* wrapped this way today because
  they always use BouncyCastle. When .NET exposes them natively, we'll add
  `Ec25519Backend.cs` and `EdSignatureBackend.cs` in the same shape.
