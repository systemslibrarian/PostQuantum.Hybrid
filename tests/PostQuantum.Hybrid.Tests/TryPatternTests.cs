using System.Security.Cryptography;
using Xunit;

namespace PostQuantum.Hybrid.Tests;

/// <summary>
/// Asserts the non-throwing TryImport / TryFromBytes / TryDecapsulate
/// counterparts of the parse and decap APIs behave as documented.
/// </summary>
public class TryPatternTests
{
    [Fact]
    public void TryImport_KemPublicKey_RoundTripsValidBlob()
    {
        using var pair = HybridKem.GenerateKeyPair();
        var bytes = pair.PublicKey.Export();

        var ok = HybridKemPublicKey.TryImport(bytes, out var imported);
        Assert.True(ok);
        Assert.NotNull(imported);
        Assert.Equal(pair.PublicKey.Export(), imported!.Export());
    }

    [Fact]
    public void TryImport_KemPublicKey_GarbageReturnsFalse()
    {
        var ok = HybridKemPublicKey.TryImport(new byte[10], out var imported);
        Assert.False(ok);
        Assert.Null(imported);
    }

    [Fact]
    public void TryImportPem_KemPublicKey_RoundTripsValidPem()
    {
        using var pair = HybridKem.GenerateKeyPair();
        var pem = pair.PublicKey.ExportPem();

        var ok = HybridKemPublicKey.TryImportPem(pem, out var imported);
        Assert.True(ok);
        Assert.NotNull(imported);
    }

    [Fact]
    public void TryImportPem_KemPublicKey_GarbagePemReturnsFalse()
    {
        var ok = HybridKemPublicKey.TryImportPem("not a pem string", out var imported);
        Assert.False(ok);
        Assert.Null(imported);
    }

    [Fact]
    public void TryImport_KemPrivateKey_DisposeOwnership()
    {
        using var pair = HybridKem.GenerateKeyPair();
        var bytes = pair.PrivateKey.Export();
        try
        {
            var ok = HybridKemPrivateKey.TryImport(bytes, out var imported);
            Assert.True(ok);
            Assert.NotNull(imported);
            imported!.Dispose(); // caller owns
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    [Fact]
    public void TryImport_SignaturePublicKey_RoundTripsValidBlob()
    {
        using var pair = HybridSignature.GenerateKeyPair();
        var bytes = pair.PublicKey.Export();
        var ok = HybridSignaturePublicKey.TryImport(bytes, out var imported);
        Assert.True(ok);
        Assert.NotNull(imported);
    }

    [Fact]
    public void TryImport_SignaturePrivateKey_GarbageReturnsFalse()
    {
        var ok = HybridSignaturePrivateKey.TryImport(new byte[7], out var imported);
        Assert.False(ok);
        Assert.Null(imported);
    }

    [Fact]
    public void TryImportPem_SignaturePublicKey_RoundTrips()
    {
        using var pair = HybridSignature.GenerateKeyPair();
        var ok = HybridSignaturePublicKey.TryImportPem(pair.PublicKey.ExportPem(), out var imported);
        Assert.True(ok);
        Assert.NotNull(imported);
    }

    [Fact]
    public void TryFromBytes_Ciphertext_RoundTripsValidBlob()
    {
        using var pair = HybridKem.GenerateKeyPair();
        using var enc = HybridKem.Encapsulate(pair.PublicKey);
        var bytes = enc.Ciphertext.ToBytes();

        var ok = HybridKemCiphertext.TryFromBytes(bytes, out var imported);
        Assert.True(ok);
        Assert.NotNull(imported);
        Assert.Equal(bytes, imported!.ToBytes());
    }

    [Fact]
    public void TryFromBytes_Ciphertext_GarbageReturnsFalse()
    {
        var ok = HybridKemCiphertext.TryFromBytes(new byte[3], out var imported);
        Assert.False(ok);
        Assert.Null(imported);
    }

    [Fact]
    public void TryDecapsulate_HappyPath_RecoversSecret()
    {
        using var pair = HybridKem.GenerateKeyPair();
        using var enc = HybridKem.Encapsulate(pair.PublicKey);

        var ok = HybridKem.TryDecapsulate(pair.PrivateKey, enc.Ciphertext, out var recovered);
        Assert.True(ok);
        Assert.NotNull(recovered);
        Assert.Equal(enc.SharedSecret, recovered);
    }

    [Fact]
    public void TryDecapsulate_BytesOverload_HappyPath()
    {
        using var pair = HybridKem.GenerateKeyPair();
        using var enc = HybridKem.Encapsulate(pair.PublicKey);
        var ctBytes = enc.Ciphertext.ToBytes();

        var ok = HybridKem.TryDecapsulate(pair.PrivateKey, ctBytes, out var recovered);
        Assert.True(ok);
        Assert.Equal(enc.SharedSecret, recovered);
    }

    [Fact]
    public void TryDecapsulate_GarbageCiphertextBytes_ReturnsFalse()
    {
        using var pair = HybridKem.GenerateKeyPair();
        var ok = HybridKem.TryDecapsulate(pair.PrivateKey, new byte[10], out var recovered);
        Assert.False(ok);
        Assert.Null(recovered);
    }

    [Fact]
    public void TryDecapsulate_DisposedPrivateKey_ReturnsFalse()
    {
        var pair = HybridKem.GenerateKeyPair();
        using var enc = HybridKem.Encapsulate(pair.PublicKey);
        pair.Dispose();

        var ok = HybridKem.TryDecapsulate(pair.PrivateKey, enc.Ciphertext, out var recovered);
        Assert.False(ok);
        Assert.Null(recovered);
    }
}
