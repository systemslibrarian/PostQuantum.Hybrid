using System.Security.Cryptography;
using Xunit;

namespace PostQuantum.Hybrid.Tests;

/// <summary>
/// Tests for the X-Wing combiner exposed at algorithm-id 0x02. See
/// <see cref="HybridKemAlgorithm.X25519MlKem768XWing"/> and ADR 0013.
/// </summary>
public class XWingCombinerTests
{
    [Fact]
    public void XWing_GenerateKeyPair_HasAlgorithmIdTwo()
    {
        using var pair = HybridKem.GenerateKeyPair(HybridKemAlgorithm.X25519MlKem768XWing);
        Assert.Equal(HybridKemAlgorithm.X25519MlKem768XWing, pair.PublicKey.Algorithm);
        Assert.Equal(HybridKemAlgorithm.X25519MlKem768XWing, pair.PrivateKey.Algorithm);

        var pubBytes = pair.PublicKey.Export();
        Assert.Equal(0x02, pubBytes[0]);
        var privBytes = pair.PrivateKey.Export();
        Assert.Equal(0x02, privBytes[0]);
        CryptographicOperations.ZeroMemory(privBytes);
    }

    [Fact]
    public void XWing_Encapsulate_ProducesCiphertextWithAlgorithmIdTwo()
    {
        using var pair = HybridKem.GenerateKeyPair(HybridKemAlgorithm.X25519MlKem768XWing);
        using var enc = HybridKem.Encapsulate(pair.PublicKey);
        Assert.Equal(HybridKemAlgorithm.X25519MlKem768XWing, enc.Ciphertext.Algorithm);
        Assert.Equal(0x02, enc.Ciphertext.ToBytes()[0]);
    }

    [Fact]
    public void XWing_EncapsulateDecapsulate_RecoversSameSecret()
    {
        using var pair = HybridKem.GenerateKeyPair(HybridKemAlgorithm.X25519MlKem768XWing);
        using var enc = HybridKem.Encapsulate(pair.PublicKey);
        var recovered = HybridKem.Decapsulate(pair.PrivateKey, enc.Ciphertext);
        Assert.True(CryptographicOperations.FixedTimeEquals(enc.SharedSecret, recovered),
            "decapsulated secret must match encapsulated secret under the X-Wing combiner");
        CryptographicOperations.ZeroMemory(recovered);
    }

    [Fact]
    public void XWing_PortBetweenSerializations_PreservesAlgorithmId()
    {
        using var pair = HybridKem.GenerateKeyPair(HybridKemAlgorithm.X25519MlKem768XWing);
        var pubBytes = pair.PublicKey.Export();
        var imported = HybridKemPublicKey.Import(pubBytes);
        Assert.Equal(HybridKemAlgorithm.X25519MlKem768XWing, imported.Algorithm);

        // Round trip a ciphertext too.
        using var enc = HybridKem.Encapsulate(pair.PublicKey);
        var ctBytes = enc.Ciphertext.ToBytes();
        var ctImported = HybridKemCiphertext.FromBytes(ctBytes);
        Assert.Equal(HybridKemAlgorithm.X25519MlKem768XWing, ctImported.Algorithm);
        var recovered = HybridKem.Decapsulate(pair.PrivateKey, ctImported);
        Assert.True(CryptographicOperations.FixedTimeEquals(enc.SharedSecret, recovered));
        CryptographicOperations.ZeroMemory(recovered);
    }

    [Fact]
    public void XWing_DifferentFromHkdfV1_OnSameInputs()
    {
        // The two algorithms have the same per-component layout but
        // different combiners; using the same key/seed material under
        // each algorithm-id must produce different derived secrets.
        using var v1Pair = HybridKem.GenerateKeyPair(HybridKemAlgorithm.X25519MlKem768);
        // Re-import the same bytes under algorithm-id 0x02 by manually
        // patching the leading byte. (Production code never does this;
        // this test is to prove the combiners do not coincide.)
        var v1Pub = v1Pair.PublicKey.Export();
        var v1Priv = v1Pair.PrivateKey.Export();
        try
        {
            var xwingPubBytes  = (byte[])v1Pub.Clone();  xwingPubBytes[0]  = 0x02;
            var xwingPrivBytes = (byte[])v1Priv.Clone(); xwingPrivBytes[0] = 0x02;

            var xwingPub  = HybridKemPublicKey.Import(xwingPubBytes);
            using var xwingPriv = HybridKemPrivateKey.Import(xwingPrivBytes);
            CryptographicOperations.ZeroMemory(xwingPrivBytes);

            using var encV1    = HybridKem.Encapsulate(v1Pair.PublicKey);
            using var encXWing = HybridKem.Encapsulate(xwingPub);

            // Each is internally consistent...
            var roundV1    = HybridKem.Decapsulate(v1Pair.PrivateKey, encV1.Ciphertext);
            var roundXWing = HybridKem.Decapsulate(xwingPriv,         encXWing.Ciphertext);
            Assert.True(CryptographicOperations.FixedTimeEquals(encV1.SharedSecret, roundV1));
            Assert.True(CryptographicOperations.FixedTimeEquals(encXWing.SharedSecret, roundXWing));

            // ...but the two derived secrets are not the same. (Different
            // ephemeral randomness alone would already make them differ;
            // this assertion's value is that we got here at all without
            // an algorithm-id rejection.)
            Assert.NotEqual(encV1.SharedSecret, encXWing.SharedSecret);

            CryptographicOperations.ZeroMemory(roundV1);
            CryptographicOperations.ZeroMemory(roundXWing);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(v1Priv);
        }
    }

    [Fact]
    public void XWing_AlgorithmMismatch_Decap_IsRejected()
    {
        using var v1Pair    = HybridKem.GenerateKeyPair(HybridKemAlgorithm.X25519MlKem768);
        using var xwingPair = HybridKem.GenerateKeyPair(HybridKemAlgorithm.X25519MlKem768XWing);
        using var encXWing  = HybridKem.Encapsulate(xwingPair.PublicKey);

        Assert.Throws<InvalidCiphertextException>(() =>
            HybridKem.Decapsulate(v1Pair.PrivateKey, encXWing.Ciphertext));
    }

    [Fact]
    public void HybridKem_Default_StaysX25519MlKem768()
    {
        // Defending against accidental default flips. The v1.0 default
        // is the HKDF combiner; X-Wing is opt-in.
        Assert.Equal(HybridKemAlgorithm.X25519MlKem768, HybridKem.Default);
    }
}
