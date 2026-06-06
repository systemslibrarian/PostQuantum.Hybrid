using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace PostQuantum.Hybrid.Tests;

public class HybridSignatureTests
{
    private static readonly byte[] Message = "The quick brown fox jumps over the lazy dog."u8.ToArray();

    [Fact]
    public void GenerateKeyPair_ProducesKeysOfExpectedSize()
    {
        using var pair = HybridSignature.GenerateKeyPair();

        Assert.Equal(HybridSignatureAlgorithm.Ed25519MlDsa65, pair.Algorithm);
        Assert.Equal(1985, pair.PublicKey.Export().Length);
        Assert.Equal(4065, pair.PrivateKey.Export().Length);
    }

    [Fact]
    public void Sign_ProducesSignatureOfExpectedSize()
    {
        using var pair = HybridSignature.GenerateKeyPair();
        var sig = HybridSignature.Sign(pair.PrivateKey, Message);
        Assert.Equal(3374, sig.Length);
    }

    [Fact]
    public void Sign_Verify_RoundTripsSuccessfully()
    {
        using var pair = HybridSignature.GenerateKeyPair();
        var sig = HybridSignature.Sign(pair.PrivateKey, Message);
        Assert.True(HybridSignature.Verify(pair.PublicKey, Message, sig));
    }

    [Fact]
    public void Verify_WrongMessage_ReturnsFalse()
    {
        using var pair = HybridSignature.GenerateKeyPair();
        var sig = HybridSignature.Sign(pair.PrivateKey, Message);
        var tamperedMessage = Encoding.UTF8.GetBytes("The slow red fox.");
        Assert.False(HybridSignature.Verify(pair.PublicKey, tamperedMessage, sig));
    }

    [Fact]
    public void Verify_WrongPublicKey_ReturnsFalse()
    {
        using var alice = HybridSignature.GenerateKeyPair();
        using var bob = HybridSignature.GenerateKeyPair();
        var sig = HybridSignature.Sign(alice.PrivateKey, Message);
        Assert.False(HybridSignature.Verify(bob.PublicKey, Message, sig));
    }

    [Fact]
    public void Verify_TamperedClassicalSig_ReturnsFalse()
    {
        using var pair = HybridSignature.GenerateKeyPair();
        var sig = HybridSignature.Sign(pair.PrivateKey, Message);
        sig[5] ^= 0xFF; // tamper Ed25519 portion
        Assert.False(HybridSignature.Verify(pair.PublicKey, Message, sig));
    }

    [Fact]
    public void Verify_TamperedPqSig_ReturnsFalse()
    {
        using var pair = HybridSignature.GenerateKeyPair();
        var sig = HybridSignature.Sign(pair.PrivateKey, Message);
        sig[sig.Length - 1] ^= 0x01; // tamper ML-DSA portion
        Assert.False(HybridSignature.Verify(pair.PublicKey, Message, sig));
    }

    [Fact]
    public void Verify_WrongLengthSignature_ReturnsFalse()
    {
        using var pair = HybridSignature.GenerateKeyPair();
        Assert.False(HybridSignature.Verify(pair.PublicKey, Message, new byte[10]));
    }

    [Fact]
    public void Verify_WrongAlgorithmId_ReturnsFalse()
    {
        using var pair = HybridSignature.GenerateKeyPair();
        var sig = HybridSignature.Sign(pair.PrivateKey, Message);
        sig[0] = 0xEE;
        Assert.False(HybridSignature.Verify(pair.PublicKey, Message, sig));
    }

    [Fact]
    public void Sign_TwoCallsProduceDifferentSignatures()
    {
        // ML-DSA signing uses randomization by default, so two signatures over
        // the same data with the same key should differ.
        using var pair = HybridSignature.GenerateKeyPair();
        var a = HybridSignature.Sign(pair.PrivateKey, Message);
        var b = HybridSignature.Sign(pair.PrivateKey, Message);
        Assert.NotEqual(a, b);
        Assert.True(HybridSignature.Verify(pair.PublicKey, Message, a));
        Assert.True(HybridSignature.Verify(pair.PublicKey, Message, b));
    }

    [Fact]
    public void PublicKey_RawSerializationRoundTrip()
    {
        using var pair = HybridSignature.GenerateKeyPair();
        var bytes = pair.PublicKey.Export();
        var roundTripped = HybridSignaturePublicKey.Import(bytes);

        var sig = HybridSignature.Sign(pair.PrivateKey, Message);
        Assert.True(HybridSignature.Verify(roundTripped, Message, sig));
    }

    [Fact]
    public void PrivateKey_RawSerializationRoundTrip()
    {
        using var pair = HybridSignature.GenerateKeyPair();
        var bytes = pair.PrivateKey.Export();
        using var roundTripped = HybridSignaturePrivateKey.Import(bytes);

        var sig = HybridSignature.Sign(roundTripped, Message);
        Assert.True(HybridSignature.Verify(pair.PublicKey, Message, sig));
    }

    [Fact]
    public void PublicKey_PemRoundTrip()
    {
        using var pair = HybridSignature.GenerateKeyPair();
        var pem = pair.PublicKey.ExportPem();

        Assert.StartsWith("-----BEGIN PQH HYBRID SIG PUBLIC KEY-----", pem);

        var roundTripped = HybridSignaturePublicKey.ImportPem(pem);
        var sig = HybridSignature.Sign(pair.PrivateKey, Message);
        Assert.True(HybridSignature.Verify(roundTripped, Message, sig));
    }

    [Fact]
    public void PrivateKey_PemRoundTrip()
    {
        using var pair = HybridSignature.GenerateKeyPair();
        var pem = pair.PrivateKey.ExportPem();

        Assert.StartsWith("-----BEGIN PQH HYBRID SIG PRIVATE KEY-----", pem);

        using var roundTripped = HybridSignaturePrivateKey.ImportPem(pem);
        var sig = HybridSignature.Sign(roundTripped, Message);
        Assert.True(HybridSignature.Verify(pair.PublicKey, Message, sig));
    }

    [Fact]
    public void Import_WrongLength_Throws()
    {
        Assert.Throws<CryptographicException>(() => HybridSignaturePublicKey.Import(new byte[10]));
        Assert.Throws<CryptographicException>(() => HybridSignaturePrivateKey.Import(new byte[10]));
    }

    [Fact]
    public void Import_UnknownAlgorithmId_Throws()
    {
        var bytes = new byte[1985];
        bytes[0] = 0xEE;
        Assert.Throws<CryptographicException>(() => HybridSignaturePublicKey.Import(bytes));
    }
}
