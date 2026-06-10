using System.Security.Cryptography;
using Xunit;

namespace PostQuantum.Hybrid.Tests;

public class HybridSharedSecretTests
{
    [Fact]
    public void Default_IsEmpty_AndLengthZero()
    {
        var s = default(HybridSharedSecret);
        Assert.True(s.IsEmpty);
        Assert.Equal(0, s.Length);
        Assert.Equal(0, s.AsSpan().Length);
        Assert.Equal(Array.Empty<byte>(), s.ToArray());
    }

    [Fact]
    public void Encapsulation_Secret_MatchesSharedSecretByteArray()
    {
        using var pair = HybridKem.GenerateKeyPair();
        using var enc = HybridKem.Encapsulate(pair.PublicKey);

        Assert.False(enc.Secret.IsEmpty);
        Assert.Equal(32, enc.Secret.Length);
        Assert.Equal(enc.SharedSecret, enc.Secret.ToArray());
        Assert.True(CryptographicOperations.FixedTimeEquals(enc.SharedSecret, enc.Secret.AsSpan()));
    }

    [Fact]
    public void ImplicitSpanConversion_FlowsIntoHkdf()
    {
        using var pair = HybridKem.GenerateKeyPair();
        using var enc = HybridKem.Encapsulate(pair.PublicKey);

        // The implicit ReadOnlySpan<byte> conversion lets the secret be passed
        // straight to HKDF without ToArray.
        var derived = new byte[32];
        HKDF.Expand(HashAlgorithmName.SHA256, enc.Secret, derived,
            info: "PostQuantum.Hybrid test"u8);

        Assert.NotEqual(new byte[32], derived);
    }

    [Fact]
    public void CopyTo_FillsDestination()
    {
        using var pair = HybridKem.GenerateKeyPair();
        using var enc = HybridKem.Encapsulate(pair.PublicKey);

        Span<byte> dest = stackalloc byte[32];
        enc.Secret.CopyTo(dest);
        Assert.True(CryptographicOperations.FixedTimeEquals(dest, enc.SharedSecret));
    }

    [Fact]
    public void Clear_ZerosUnderlyingSecret_VisibleViaSharedSecret()
    {
        using var pair = HybridKem.GenerateKeyPair();
        using var enc = HybridKem.Encapsulate(pair.PublicKey);

        Assert.False(enc.SharedSecret.All(b => b == 0));
        enc.Secret.Clear();
        // Clear on the typed wrapper zeroes the same backing buffer.
        Assert.True(enc.SharedSecret.All(b => b == 0));
    }

    [Fact]
    public void Clear_OnLocalVariable_MakesReceiverEquivalentToDefault()
    {
        using var pair = HybridKem.GenerateKeyPair();
        using var enc = HybridKem.Encapsulate(pair.PublicKey);

        var secret = enc.Secret;
        Assert.False(secret.IsEmpty);
        Assert.Equal(32, secret.Length);
        Assert.Equal(32, secret.AsSpan().Length);

        secret.Clear();

        // After Clear, the receiver is equivalent to default(HybridSharedSecret).
        Assert.True(secret.IsEmpty);
        Assert.Equal(0, secret.Length);
        Assert.Equal(0, secret.AsSpan().Length);
        Assert.Equal(Array.Empty<byte>(), secret.ToArray());
    }

    [Fact]
    public void Secret_OnDisposedResult_Throws()
    {
        var pair = HybridKem.GenerateKeyPair();
        var enc = HybridKem.Encapsulate(pair.PublicKey);
        enc.Dispose();

        Assert.Throws<ObjectDisposedException>(() => enc.Secret);
        pair.Dispose();
    }
}
