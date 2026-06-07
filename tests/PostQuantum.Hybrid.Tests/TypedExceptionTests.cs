using System.Security.Cryptography;
using Xunit;

namespace PostQuantum.Hybrid.Tests;

/// <summary>
/// Asserts that the typed exception subclasses are thrown from the
/// expected parse failures, and that the base-class and
/// <see cref="CryptographicException"/> contracts still hold so that
/// existing callers do not need to change.
/// </summary>
public class TypedExceptionTests
{
    [Fact]
    public void KemPublicKeyImport_WrongLength_ThrowsHybridKeyParseException()
    {
        var ex = Assert.Throws<HybridKeyParseException>(
            () => HybridKemPublicKey.Import(new byte[10]));
        Assert.Equal(HybridFailureReason.InvalidLength, ex.Reason);
    }

    [Fact]
    public void KemPublicKeyImport_BadAlgorithmId_ThrowsHybridKeyParseException()
    {
        var bad = new byte[1217];
        bad[0] = 0xFE;
        var ex = Assert.Throws<HybridKeyParseException>(() => HybridKemPublicKey.Import(bad));
        Assert.Equal(HybridFailureReason.UnsupportedAlgorithmId, ex.Reason);
    }

    [Fact]
    public void KemPrivateKeyImport_WrongLength_ThrowsHybridKeyParseException()
    {
        Assert.Throws<HybridKeyParseException>(
            () => HybridKemPrivateKey.Import(new byte[10]));
    }

    [Fact]
    public void SignaturePublicKeyImport_WrongLength_ThrowsHybridKeyParseException()
    {
        Assert.Throws<HybridKeyParseException>(
            () => HybridSignaturePublicKey.Import(new byte[10]));
    }

    [Fact]
    public void SignaturePrivateKeyImport_WrongLength_ThrowsHybridKeyParseException()
    {
        Assert.Throws<HybridKeyParseException>(
            () => HybridSignaturePrivateKey.Import(new byte[10]));
    }

    [Fact]
    public void CiphertextFromBytes_WrongLength_ThrowsInvalidCiphertextException()
    {
        var ex = Assert.Throws<InvalidCiphertextException>(
            () => HybridKemCiphertext.FromBytes(new byte[10]));
        Assert.Equal(HybridFailureReason.InvalidLength, ex.Reason);
    }

    [Fact]
    public void CiphertextFromBytes_BadAlgorithmId_ThrowsInvalidCiphertextException()
    {
        var bad = new byte[1121];
        bad[0] = 0xFE;
        var ex = Assert.Throws<InvalidCiphertextException>(() => HybridKemCiphertext.FromBytes(bad));
        Assert.Equal(HybridFailureReason.UnsupportedAlgorithmId, ex.Reason);
    }

    [Fact]
    public void TypedExceptions_AreCatchableAsPostQuantumHybridException()
    {
        try
        {
            HybridKemPublicKey.Import(new byte[10]);
            Assert.Fail("expected throw");
        }
        catch (PostQuantumHybridException ex)
        {
            // Still works for callers that switch on Reason.
            Assert.Equal(HybridFailureReason.InvalidLength, ex.Reason);
        }
    }

    [Fact]
    public void TypedExceptions_AreCatchableAsCryptographicException()
    {
        try
        {
            HybridKemCiphertext.FromBytes(new byte[10]);
            Assert.Fail("expected throw");
        }
        catch (CryptographicException)
        {
            // Still works for the broadest catch clause.
        }
    }
}
