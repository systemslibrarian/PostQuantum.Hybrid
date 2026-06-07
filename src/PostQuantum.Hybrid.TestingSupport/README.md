# PostQuantum.Hybrid.TestingSupport

Test helpers for projects that consume
[PostQuantum.Hybrid](https://github.com/systemslibrarian/PostQuantum.Hybrid).

## Install

```bash
dotnet add package PostQuantum.Hybrid.TestingSupport
```

## What's in the box

| API | Use |
|---|---|
| `HybridTestKeys.SharedKemPair` / `SharedSignaturePair` | Lazily-cached, process-wide key pair. Skips the 300 ms keygen cost when many tests need *a* key pair but don't care which one. |
| `HybridTestKeys.GenerateFresh*KeyPair()` | Fresh key pair per call. Use when each test must have its own. |
| `HybridTamper.FlipBit(bytes, byteIndex, bitIndex)` | Returns a copy of `bytes` with the specified bit flipped — exact-position tamper injection. |
| `HybridTamper.FlipRandomBit(bytes, seed)` | Deterministically pseudorandom single-bit flip from a seed. |
| `HybridTamper.TruncateBy(bytes, count)` / `ExtendBy(bytes, count)` | Length-tamper helpers. |
| `FakeHybridKemKeyProvider(pair)` / `FakeHybridSignatureKeyProvider(pair)` | Minimal `IHybridKemKeyProvider` / `IHybridSignatureKeyProvider` implementations for unit tests that wire through the `PostQuantum.Hybrid.AspNetCore` abstractions without spinning a real host. |

## Quick start

```csharp
using PostQuantum.Hybrid;
using PostQuantum.Hybrid.TestingSupport;
using Xunit;

public class MyEnvelopeTests
{
    [Fact]
    public void RoundTrips()
    {
        var pair = HybridTestKeys.SharedKemPair;
        using var enc = HybridKem.Encapsulate(pair.PublicKey);
        var dec = HybridKem.Decapsulate(pair.PrivateKey, enc.Ciphertext);
        Assert.Equal(enc.SharedSecret, dec);
    }

    [Fact]
    public void Decapsulate_TamperedCiphertext_ProducesDifferentSecret()
    {
        var pair = HybridTestKeys.SharedKemPair;
        using var enc = HybridKem.Encapsulate(pair.PublicKey);

        var tampered = HybridTamper.FlipBit(enc.Ciphertext.ToBytes(), byteIndex: 50, bitIndex: 0);
        var ct = HybridKemCiphertext.FromBytes(tampered);

        var dec = HybridKem.Decapsulate(pair.PrivateKey, ct);
        Assert.NotEqual(enc.SharedSecret, dec);
    }
}
```

## Notes on shared keys

`HybridTestKeys.SharedKemPair` and `SharedSignaturePair` cache one key
pair per process. They are safe to use across parallel xUnit tests
because key generation is one-shot and the resulting key pair is
immutable.

**Do not use the shared keys in tests that mutate or dispose them.**
If you need to dispose, generate a fresh pair instead.
