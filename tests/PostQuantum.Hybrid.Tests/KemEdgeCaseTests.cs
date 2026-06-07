using System.Security.Cryptography;
using Xunit;

namespace PostQuantum.Hybrid.Tests;

public class KemEdgeCaseTests
{
    [Fact]
    public void Decapsulate_ByteSpan_OverloadEqualsTypedOverload()
    {
        using var pair = HybridKem.GenerateKeyPair();
        using var enc = HybridKem.Encapsulate(pair.PublicKey);

        var viaTyped = HybridKem.Decapsulate(pair.PrivateKey, enc.Ciphertext);
        var viaBytes = HybridKem.Decapsulate(pair.PrivateKey, enc.Ciphertext.ToBytes());
        Assert.Equal(viaTyped, viaBytes);
    }

    [Fact]
    public void ManyRoundTrips_AllProduceMatchingSecrets()
    {
        using var pair = HybridKem.GenerateKeyPair();
        for (var i = 0; i < 25; i++)
        {
            using var enc = HybridKem.Encapsulate(pair.PublicKey);
            var dec = HybridKem.Decapsulate(pair.PrivateKey, enc.Ciphertext);
            Assert.Equal(enc.SharedSecret, dec);
        }
    }

    [Fact]
    public void TenFreshKeyPairs_AllRoundTripIndependently()
    {
        for (var i = 0; i < 10; i++)
        {
            using var pair = HybridKem.GenerateKeyPair();
            using var enc = HybridKem.Encapsulate(pair.PublicKey);
            var dec = HybridKem.Decapsulate(pair.PrivateKey, enc.Ciphertext);
            Assert.Equal(enc.SharedSecret, dec);
        }
    }

    [Fact]
    public void TwoFreshKeyPairs_ProduceDifferentPublicKeys()
    {
        using var a = HybridKem.GenerateKeyPair();
        using var b = HybridKem.GenerateKeyPair();
        Assert.NotEqual(a.PublicKey.Export(), b.PublicKey.Export());
        Assert.NotEqual(a.PrivateKey.Export(), b.PrivateKey.Export());
    }

    [Fact]
    public void Decapsulate_OnDisposedPrivateKey_Throws()
    {
        var pair = HybridKem.GenerateKeyPair();
        using var enc = HybridKem.Encapsulate(pair.PublicKey);
        pair.PrivateKey.Dispose();
        Assert.Throws<ObjectDisposedException>(() => HybridKem.Decapsulate(pair.PrivateKey, enc.Ciphertext));
    }

    [Fact]
    public void Encapsulate_NullPublicKey_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => HybridKem.Encapsulate(null!));
    }

    [Fact]
    public void Decapsulate_NullArgs_Throw()
    {
        using var pair = HybridKem.GenerateKeyPair();
        using var enc = HybridKem.Encapsulate(pair.PublicKey);
        Assert.Throws<ArgumentNullException>(() => HybridKem.Decapsulate(null!, enc.Ciphertext));
        Assert.Throws<ArgumentNullException>(() => HybridKem.Decapsulate(pair.PrivateKey, (HybridKemCiphertext)null!));
    }

    [Fact]
    public void Ciphertext_FromBytes_OneByteShort_Throws()
    {
        using var pair = HybridKem.GenerateKeyPair();
        using var enc = HybridKem.Encapsulate(pair.PublicKey);
        var bytes = enc.Ciphertext.ToBytes();
        Assert.ThrowsAny<CryptographicException>(() => HybridKemCiphertext.FromBytes(bytes.AsSpan(0, bytes.Length - 1)));
    }

    [Fact]
    public void Ciphertext_FromBytes_OneByteExtra_Throws()
    {
        using var pair = HybridKem.GenerateKeyPair();
        using var enc = HybridKem.Encapsulate(pair.PublicKey);
        var bytes = enc.Ciphertext.ToBytes();
        var padded = new byte[bytes.Length + 1];
        bytes.CopyTo(padded, 0);
        Assert.ThrowsAny<CryptographicException>(() => HybridKemCiphertext.FromBytes(padded));
    }

    [Fact]
    public void Decapsulate_OfImplicitlyRejectedCiphertext_ReturnsDeterministicallyWrongSecret()
    {
        // Two independent decapsulations of the same tampered ciphertext must
        // produce the same wrong secret (deterministic, implicit-rejection
        // behavior of ML-KEM). This rules out non-deterministic decap bugs.
        using var pair = HybridKem.GenerateKeyPair();
        using var enc = HybridKem.Encapsulate(pair.PublicKey);
        var bytes = enc.Ciphertext.ToBytes();
        bytes[bytes.Length - 1] ^= 0xAA;

        var tampered = HybridKemCiphertext.FromBytes(bytes);
        var a = HybridKem.Decapsulate(pair.PrivateKey, tampered);
        var b = HybridKem.Decapsulate(pair.PrivateKey, tampered);
        Assert.Equal(a, b);
        Assert.NotEqual(enc.SharedSecret, a);
    }
}
