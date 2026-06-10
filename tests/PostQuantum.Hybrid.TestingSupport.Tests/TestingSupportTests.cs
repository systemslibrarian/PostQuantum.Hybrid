using PostQuantum.Hybrid;
using PostQuantum.Hybrid.TestingSupport;
using Xunit;

namespace PostQuantum.Hybrid.TestingSupport.Tests;

public class HybridTestKeysTests
{
    [Fact]
    public void SharedKemPair_ReturnsSameInstance()
    {
        var a = HybridTestKeys.SharedKemPair;
        var b = HybridTestKeys.SharedKemPair;
        Assert.Same(a, b);
    }

    [Fact]
    public void SharedSignaturePair_ReturnsSameInstance()
    {
        var a = HybridTestKeys.SharedSignaturePair;
        var b = HybridTestKeys.SharedSignaturePair;
        Assert.Same(a, b);
    }

    [Fact]
    public void SharedKemPair_IsUsable()
    {
        var pair = HybridTestKeys.SharedKemPair;
        using var enc = HybridKem.Encapsulate(pair.PublicKey);
        var dec = HybridKem.Decapsulate(pair.PrivateKey, enc.Ciphertext);
        Assert.Equal(enc.SharedSecret, dec);
    }

    [Fact]
    public void GenerateFreshKemKeyPair_IsAlwaysNew()
    {
        using var a = HybridTestKeys.GenerateFreshKemKeyPair();
        using var b = HybridTestKeys.GenerateFreshKemKeyPair();
        Assert.NotEqual(a.PublicKey.Export(), b.PublicKey.Export());
    }

    [Fact]
    public void GenerateFreshSignatureKeyPair_IsAlwaysNew()
    {
        using var a = HybridTestKeys.GenerateFreshSignatureKeyPair();
        using var b = HybridTestKeys.GenerateFreshSignatureKeyPair();
        Assert.NotEqual(a.PublicKey.Export(), b.PublicKey.Export());
    }
}

public class HybridTamperTests
{
    [Fact]
    public void FlipBit_FlipsExactlyOneBit()
    {
        var original = new byte[] { 0b1111_0000 };
        var flipped = HybridTamper.FlipBit(original, 0, 0);
        Assert.Equal(0b1111_0001, flipped[0]);
    }

    [Fact]
    public void FlipBit_OnByteIndexOutOfRange_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => HybridTamper.FlipBit(new byte[1], 5, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => HybridTamper.FlipBit(new byte[1], -1, 0));
    }

    [Fact]
    public void FlipBit_OnBitIndexOutOfRange_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => HybridTamper.FlipBit(new byte[1], 0, 8));
        Assert.Throws<ArgumentOutOfRangeException>(() => HybridTamper.FlipBit(new byte[1], 0, -1));
    }

    [Fact]
    public void FlipRandomBit_IsDeterministicForSameSeed()
    {
        var bytes = new byte[100];
        new Random(42).NextBytes(bytes);
        var a = HybridTamper.FlipRandomBit(bytes, seed: 7);
        var b = HybridTamper.FlipRandomBit(bytes, seed: 7);
        Assert.Equal(a, b);
        Assert.NotEqual(bytes, a);
    }

    [Fact]
    public void TruncateBy_RemovesTailBytes()
    {
        var bytes = new byte[] { 1, 2, 3, 4, 5 };
        var t = HybridTamper.TruncateBy(bytes, 2);
        Assert.Equal(new byte[] { 1, 2, 3 }, t);
    }

    [Fact]
    public void ExtendBy_AppendsZeros()
    {
        var bytes = new byte[] { 1, 2, 3 };
        var e = HybridTamper.ExtendBy(bytes, 2);
        Assert.Equal(new byte[] { 1, 2, 3, 0, 0 }, e);
    }
}

public class FakeProvidersTests
{
    [Fact]
    public void FakeKemProvider_ExposesGivenKeyPair()
    {
        using var pair = HybridKem.GenerateKeyPair();
        using var provider = new FakeHybridKemKeyProvider(pair);
        Assert.Same(pair.PublicKey, provider.PublicKey);
        Assert.Same(pair.PrivateKey, provider.PrivateKey);
    }

    [Fact]
    public void FakeKemProvider_DefaultCtor_GeneratesOne()
    {
        using var provider = new FakeHybridKemKeyProvider();
        Assert.NotNull(provider.PublicKey);
        Assert.NotNull(provider.PrivateKey);
    }

    [Fact]
    public void FakeSignatureProvider_ExposesGivenKeyPair()
    {
        using var pair = HybridSignature.GenerateKeyPair();
        using var provider = new FakeHybridSignatureKeyProvider(pair);
        Assert.Same(pair.PublicKey, provider.PublicKey);
        Assert.Same(pair.PrivateKey, provider.PrivateKey);
    }

    [Fact]
    public void FakeKemProvider_End2End_RoundTrips()
    {
        using var provider = new FakeHybridKemKeyProvider();
        using var enc = HybridKem.Encapsulate(provider.PublicKey);
        var dec = HybridKem.Decapsulate(provider.PrivateKey, enc.Ciphertext);
        Assert.Equal(enc.SharedSecret, dec);
    }

    [Fact]
    public void FakeKemProvider_PairCtor_DoesNotDisposeCallerOwnedPair()
    {
        using var pair = HybridKem.GenerateKeyPair();
        var provider = new FakeHybridKemKeyProvider(pair);
        provider.Dispose();
        // Caller's pair must remain usable.
        Assert.NotEmpty(pair.PrivateKey.Export());
        Assert.NotEmpty(pair.PublicKey.Export());
    }

    [Fact]
    public void FakeKemProvider_SharedKemPair_SurvivesProviderDispose()
    {
        // Regression: wrapping HybridTestKeys.SharedKemPair (process-wide
        // shared) in a fake provider and disposing the provider must NOT
        // poison the shared pair.
        var shared = HybridTestKeys.SharedKemPair;
        var provider = new FakeHybridKemKeyProvider(shared);
        provider.Dispose();
        Assert.NotEmpty(shared.PrivateKey.Export());
        // The shared pair must still round-trip a fresh encap/decap.
        using var enc = HybridKem.Encapsulate(shared.PublicKey);
        var dec = HybridKem.Decapsulate(shared.PrivateKey, enc.Ciphertext);
        Assert.Equal(enc.SharedSecret, dec);
    }

    [Fact]
    public void FakeKemProvider_DefaultCtor_DisposesOwnedPair()
    {
        var provider = new FakeHybridKemKeyProvider();
        var priv = provider.PrivateKey;
        provider.Dispose();
        Assert.Throws<ObjectDisposedException>(() => priv.Export());
    }

    [Fact]
    public void FakeSignatureProvider_PairCtor_DoesNotDisposeCallerOwnedPair()
    {
        using var pair = HybridSignature.GenerateKeyPair();
        var provider = new FakeHybridSignatureKeyProvider(pair);
        provider.Dispose();
        Assert.NotEmpty(pair.PrivateKey.Export());
        Assert.NotEmpty(pair.PublicKey.Export());
    }

    [Fact]
    public void FakeSignatureProvider_SharedSignaturePair_SurvivesProviderDispose()
    {
        var shared = HybridTestKeys.SharedSignaturePair;
        var provider = new FakeHybridSignatureKeyProvider(shared);
        provider.Dispose();
        Assert.NotEmpty(shared.PrivateKey.Export());
        var sig = HybridSignature.Sign(shared.PrivateKey, "abc"u8);
        Assert.True(HybridSignature.Verify(shared.PublicKey, "abc"u8, sig));
    }

    [Fact]
    public void FakeSignatureProvider_DefaultCtor_DisposesOwnedPair()
    {
        var provider = new FakeHybridSignatureKeyProvider();
        var priv = provider.PrivateKey;
        provider.Dispose();
        Assert.Throws<ObjectDisposedException>(() => priv.Export());
    }
}
