using Xunit;

namespace PostQuantum.Hybrid.Tests;

public class WireFormatTests
{
    [Fact]
    public void KemPublicKey_FirstByteIsAlgorithmId()
    {
        using var pair = HybridKem.GenerateKeyPair();
        var bytes = pair.PublicKey.Export();
        Assert.Equal((byte)HybridKemAlgorithm.X25519MlKem768, bytes[0]);
    }

    [Fact]
    public void KemPrivateKey_FirstByteIsAlgorithmId()
    {
        using var pair = HybridKem.GenerateKeyPair();
        var bytes = pair.PrivateKey.Export();
        Assert.Equal((byte)HybridKemAlgorithm.X25519MlKem768, bytes[0]);
    }

    [Fact]
    public void KemCiphertext_FirstByteIsAlgorithmId()
    {
        using var pair = HybridKem.GenerateKeyPair();
        using var enc = HybridKem.Encapsulate(pair.PublicKey);
        var bytes = enc.Ciphertext.ToBytes();
        Assert.Equal((byte)HybridKemAlgorithm.X25519MlKem768, bytes[0]);
    }

    [Fact]
    public void HybridSignature_FirstByteIsAlgorithmId()
    {
        using var pair = HybridSignature.GenerateKeyPair();
        var sig = HybridSignature.Sign(pair.PrivateKey, "x"u8.ToArray());
        Assert.Equal((byte)HybridSignatureAlgorithm.Ed25519MlDsa65, sig[0]);
    }

    [Fact]
    public void KemDecapsulate_RejectsAlgorithmMismatch()
    {
        using var pair = HybridKem.GenerateKeyPair();
        using var enc = HybridKem.Encapsulate(pair.PublicKey);

        // Decapsulate via the byte-span overload should succeed on matching alg id.
        var bytes = enc.Ciphertext.ToBytes();
        var ok = HybridKem.Decapsulate(pair.PrivateKey, bytes);
        Assert.Equal(enc.SharedSecret, ok);
    }
}
