using System.Security.Cryptography;
using Xunit;

namespace PostQuantum.Hybrid.Tests;

public class HybridKemTests
{
    [Fact]
    public void GenerateKeyPair_ProducesNonEmptyKeysOfExpectedSize()
    {
        using var pair = HybridKem.GenerateKeyPair();

        Assert.Equal(HybridKemAlgorithm.X25519MlKem768, pair.Algorithm);
        Assert.Equal(1217, pair.PublicKey.Export().Length);
        Assert.Equal(2433, pair.PrivateKey.Export().Length);
    }

    [Fact]
    public void Encapsulate_Decapsulate_RoundTripsSharedSecret()
    {
        using var pair = HybridKem.GenerateKeyPair();

        using var enc = HybridKem.Encapsulate(pair.PublicKey);
        var decapsulated = HybridKem.Decapsulate(pair.PrivateKey, enc.Ciphertext);

        Assert.Equal(32, enc.SharedSecret.Length);
        Assert.Equal(32, decapsulated.Length);
        Assert.Equal(enc.SharedSecret, decapsulated);
    }

    [Fact]
    public void Encapsulate_ProducesDifferentCiphertextsAndSecretsEachCall()
    {
        using var pair = HybridKem.GenerateKeyPair();

        using var a = HybridKem.Encapsulate(pair.PublicKey);
        using var b = HybridKem.Encapsulate(pair.PublicKey);

        Assert.NotEqual(a.Ciphertext.ToBytes(), b.Ciphertext.ToBytes());
        Assert.NotEqual(a.SharedSecret, b.SharedSecret);
    }

    [Fact]
    public void Decapsulate_WithWrongPrivateKey_ProducesDifferentSecret()
    {
        using var alice = HybridKem.GenerateKeyPair();
        using var bob = HybridKem.GenerateKeyPair();

        using var enc = HybridKem.Encapsulate(alice.PublicKey);
        var wrongSecret = HybridKem.Decapsulate(bob.PrivateKey, enc.Ciphertext);

        Assert.NotEqual(enc.SharedSecret, wrongSecret);
    }

    [Fact]
    public void Decapsulate_WithTamperedClassicalPart_ProducesDifferentSecret()
    {
        using var pair = HybridKem.GenerateKeyPair();
        using var enc = HybridKem.Encapsulate(pair.PublicKey);

        var bytes = enc.Ciphertext.ToBytes();
        bytes[5] ^= 0xFF; // flip a bit in the X25519 ephemeral pub
        var tampered = HybridKemCiphertext.FromBytes(bytes);

        var secret = HybridKem.Decapsulate(pair.PrivateKey, tampered);
        Assert.NotEqual(enc.SharedSecret, secret);
    }

    [Fact]
    public void Decapsulate_WithTamperedPqPart_ProducesDifferentSecret()
    {
        using var pair = HybridKem.GenerateKeyPair();
        using var enc = HybridKem.Encapsulate(pair.PublicKey);

        var bytes = enc.Ciphertext.ToBytes();
        bytes[bytes.Length - 1] ^= 0x01; // flip a bit in the ML-KEM ciphertext
        var tampered = HybridKemCiphertext.FromBytes(bytes);

        var secret = HybridKem.Decapsulate(pair.PrivateKey, tampered);
        Assert.NotEqual(enc.SharedSecret, secret);
    }

    [Fact]
    public void PublicKey_RawSerializationRoundTrip()
    {
        using var pair = HybridKem.GenerateKeyPair();
        var bytes = pair.PublicKey.Export();
        var roundTripped = HybridKemPublicKey.Import(bytes);

        using var enc = HybridKem.Encapsulate(roundTripped);
        var secret = HybridKem.Decapsulate(pair.PrivateKey, enc.Ciphertext);
        Assert.Equal(enc.SharedSecret, secret);
    }

    [Fact]
    public void PrivateKey_RawSerializationRoundTrip()
    {
        using var pair = HybridKem.GenerateKeyPair();
        var bytes = pair.PrivateKey.Export();
        using var roundTripped = HybridKemPrivateKey.Import(bytes);

        using var enc = HybridKem.Encapsulate(pair.PublicKey);
        var secret = HybridKem.Decapsulate(roundTripped, enc.Ciphertext);
        Assert.Equal(enc.SharedSecret, secret);
    }

    [Fact]
    public void Ciphertext_RawSerializationRoundTrip()
    {
        using var pair = HybridKem.GenerateKeyPair();
        using var enc = HybridKem.Encapsulate(pair.PublicKey);

        var bytes = enc.Ciphertext.ToBytes();
        var roundTripped = HybridKemCiphertext.FromBytes(bytes);
        var secret = HybridKem.Decapsulate(pair.PrivateKey, roundTripped);

        Assert.Equal(enc.SharedSecret, secret);
    }

    [Fact]
    public void PublicKey_PemRoundTrip()
    {
        using var pair = HybridKem.GenerateKeyPair();
        var pem = pair.PublicKey.ExportPem();

        Assert.StartsWith("-----BEGIN PQH HYBRID KEM PUBLIC KEY-----", pem);
        Assert.Contains("-----END PQH HYBRID KEM PUBLIC KEY-----", pem);

        var roundTripped = HybridKemPublicKey.ImportPem(pem);
        using var enc = HybridKem.Encapsulate(roundTripped);
        var secret = HybridKem.Decapsulate(pair.PrivateKey, enc.Ciphertext);
        Assert.Equal(enc.SharedSecret, secret);
    }

    [Fact]
    public void PrivateKey_PemRoundTrip()
    {
        using var pair = HybridKem.GenerateKeyPair();
        var pem = pair.PrivateKey.ExportPem();

        Assert.StartsWith("-----BEGIN PQH HYBRID KEM PRIVATE KEY-----", pem);

        using var roundTripped = HybridKemPrivateKey.ImportPem(pem);
        using var enc = HybridKem.Encapsulate(pair.PublicKey);
        var secret = HybridKem.Decapsulate(roundTripped, enc.Ciphertext);
        Assert.Equal(enc.SharedSecret, secret);
    }

    [Fact]
    public void Import_WrongLength_Throws()
    {
        Assert.Throws<CryptographicException>(() => HybridKemPublicKey.Import(new byte[10]));
        Assert.Throws<CryptographicException>(() => HybridKemPrivateKey.Import(new byte[10]));
        Assert.Throws<CryptographicException>(() => HybridKemCiphertext.FromBytes(new byte[10]));
    }

    [Fact]
    public void Import_UnknownAlgorithmId_Throws()
    {
        var bytes = new byte[1217];
        bytes[0] = 0xEE;
        Assert.Throws<CryptographicException>(() => HybridKemPublicKey.Import(bytes));
    }

    [Fact]
    public void PrivateKey_AfterDispose_ThrowsOnExport()
    {
        var pair = HybridKem.GenerateKeyPair();
        pair.PrivateKey.Dispose();
        Assert.Throws<ObjectDisposedException>(() => pair.PrivateKey.Export());
    }

    [Fact]
    public void EncapsulationResult_AfterDispose_ThrowsOnSharedSecretAccess()
    {
        using var pair = HybridKem.GenerateKeyPair();
        var enc = HybridKem.Encapsulate(pair.PublicKey);
        enc.Dispose();
        Assert.Throws<ObjectDisposedException>(() => enc.SharedSecret);
    }
}
