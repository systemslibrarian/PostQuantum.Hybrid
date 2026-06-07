using System.Security.Cryptography;
using Xunit;

namespace PostQuantum.Hybrid.Tests;

public class PemRobustnessTests
{
    [Fact]
    public void ImportPem_AcceptsCrlfLineEndings()
    {
        using var pair = HybridKem.GenerateKeyPair();
        var pem = pair.PublicKey.ExportPem().Replace("\n", "\r\n");
        var roundTripped = HybridKemPublicKey.ImportPem(pem);
        using var enc = HybridKem.Encapsulate(roundTripped);
        var secret = HybridKem.Decapsulate(pair.PrivateKey, enc.Ciphertext);
        Assert.Equal(enc.SharedSecret, secret);
    }

    [Fact]
    public void ImportPem_AcceptsTrailingWhitespace()
    {
        using var pair = HybridKem.GenerateKeyPair();
        var pem = pair.PublicKey.ExportPem() + "\n\n   \n";
        var roundTripped = HybridKemPublicKey.ImportPem(pem);
        Assert.Equal(pair.PublicKey.Export(), roundTripped.Export());
    }

    [Fact]
    public void ImportPem_AcceptsLeadingWhitespace()
    {
        using var pair = HybridKem.GenerateKeyPair();
        var pem = "   \n\n" + pair.PublicKey.ExportPem();
        var roundTripped = HybridKemPublicKey.ImportPem(pem);
        Assert.Equal(pair.PublicKey.Export(), roundTripped.Export());
    }

    [Fact]
    public void ImportPem_MissingBeginMarker_Throws()
    {
        using var pair = HybridKem.GenerateKeyPair();
        var pem = pair.PublicKey.ExportPem();
        var broken = pem.Replace("-----BEGIN PQH HYBRID KEM PUBLIC KEY-----", "");
        Assert.Throws<FormatException>(() => HybridKemPublicKey.ImportPem(broken));
    }

    [Fact]
    public void ImportPem_MissingEndMarker_Throws()
    {
        using var pair = HybridKem.GenerateKeyPair();
        var pem = pair.PublicKey.ExportPem();
        var broken = pem.Replace("-----END PQH HYBRID KEM PUBLIC KEY-----", "");
        Assert.Throws<FormatException>(() => HybridKemPublicKey.ImportPem(broken));
    }

    [Fact]
    public void ImportPem_WrongLabel_Throws()
    {
        using var pair = HybridKem.GenerateKeyPair();
        var pem = pair.PublicKey.ExportPem();
        // Try to import a KEM public key as a signature public key.
        Assert.Throws<FormatException>(() => HybridSignaturePublicKey.ImportPem(pem));
    }

    [Fact]
    public void ImportPem_InvalidBase64_Throws()
    {
        var pem = """
            -----BEGIN PQH HYBRID KEM PUBLIC KEY-----
            !!!not base 64!!!
            -----END PQH HYBRID KEM PUBLIC KEY-----
            """;
        Assert.Throws<FormatException>(() => HybridKemPublicKey.ImportPem(pem));
    }

    [Fact]
    public void ImportPem_ValidBase64ButWrongLength_Throws()
    {
        // Empty body parses base64 to zero bytes; that fails the algorithm-id length check.
        var pem = """
            -----BEGIN PQH HYBRID KEM PUBLIC KEY-----
            -----END PQH HYBRID KEM PUBLIC KEY-----
            """;
        Assert.ThrowsAny<CryptographicException>(() => HybridKemPublicKey.ImportPem(pem));
    }

    [Fact]
    public void ExportPem_RoundTripsForAllFourKeyTypes()
    {
        using var kemPair = HybridKem.GenerateKeyPair();
        using var sigPair = HybridSignature.GenerateKeyPair();

        var kemPub = HybridKemPublicKey.ImportPem(kemPair.PublicKey.ExportPem());
        using var kemPriv = HybridKemPrivateKey.ImportPem(kemPair.PrivateKey.ExportPem());
        var sigPub = HybridSignaturePublicKey.ImportPem(sigPair.PublicKey.ExportPem());
        using var sigPriv = HybridSignaturePrivateKey.ImportPem(sigPair.PrivateKey.ExportPem());

        Assert.Equal(kemPair.PublicKey.Export(), kemPub.Export());
        Assert.Equal(kemPair.PrivateKey.Export(), kemPriv.Export());
        Assert.Equal(sigPair.PublicKey.Export(), sigPub.Export());
        Assert.Equal(sigPair.PrivateKey.Export(), sigPriv.Export());
    }
}
