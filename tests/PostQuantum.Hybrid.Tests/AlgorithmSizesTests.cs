using Xunit;

namespace PostQuantum.Hybrid.Tests;

/// <summary>
/// These tests pin the wire-format byte counts. The values here are the
/// public contract advertised in docs/SPEC.md; any change here is a
/// breaking change.
/// </summary>
public class AlgorithmSizesTests
{
    [Fact]
    public void HybridKemPublicKey_Is1217Bytes()
    {
        using var p = HybridKem.GenerateKeyPair();
        Assert.Equal(1217, p.PublicKey.Export().Length);
    }

    [Fact]
    public void HybridKemPrivateKey_Is2433Bytes()
    {
        using var p = HybridKem.GenerateKeyPair();
        Assert.Equal(2433, p.PrivateKey.Export().Length);
    }

    [Fact]
    public void HybridKemCiphertext_Is1121Bytes()
    {
        using var p = HybridKem.GenerateKeyPair();
        using var enc = HybridKem.Encapsulate(p.PublicKey);
        Assert.Equal(1121, enc.Ciphertext.ToBytes().Length);
    }

    [Fact]
    public void HybridKemSharedSecret_Is32Bytes()
    {
        using var p = HybridKem.GenerateKeyPair();
        using var enc = HybridKem.Encapsulate(p.PublicKey);
        Assert.Equal(32, enc.SharedSecret.Length);
    }

    [Fact]
    public void HybridSignaturePublicKey_Is1985Bytes()
    {
        using var p = HybridSignature.GenerateKeyPair();
        Assert.Equal(1985, p.PublicKey.Export().Length);
    }

    [Fact]
    public void HybridSignaturePrivateKey_Is4065Bytes()
    {
        using var p = HybridSignature.GenerateKeyPair();
        Assert.Equal(4065, p.PrivateKey.Export().Length);
    }

    [Fact]
    public void HybridSignature_Is3374Bytes()
    {
        using var p = HybridSignature.GenerateKeyPair();
        var sig = HybridSignature.Sign(p.PrivateKey, new byte[10]);
        Assert.Equal(3374, sig.Length);
    }

    [Fact]
    public void KemAlgorithmId_IsOne()
    {
        using var p = HybridKem.GenerateKeyPair();
        Assert.Equal(0x01, p.PublicKey.Export()[0]);
        Assert.Equal(0x01, p.PrivateKey.Export()[0]);
        using var enc = HybridKem.Encapsulate(p.PublicKey);
        Assert.Equal(0x01, enc.Ciphertext.ToBytes()[0]);
    }

    [Fact]
    public void SignatureAlgorithmId_IsOne()
    {
        using var p = HybridSignature.GenerateKeyPair();
        Assert.Equal(0x01, p.PublicKey.Export()[0]);
        Assert.Equal(0x01, p.PrivateKey.Export()[0]);
        var sig = HybridSignature.Sign(p.PrivateKey, new byte[10]);
        Assert.Equal(0x01, sig[0]);
    }
}
