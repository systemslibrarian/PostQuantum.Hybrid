using System.Security.Cryptography;
using System.Text;
using PostQuantum.Hybrid;
using PostQuantum.Hybrid.Envelopes;
using Xunit;

namespace PostQuantum.Hybrid.Envelopes.Tests;

public class HybridEnvelopeTests
{
    private static readonly byte[] Plaintext =
        Encoding.UTF8.GetBytes("the quick brown fox jumps over the lazy dog");

    [Fact]
    public void Seal_Open_RoundTrip()
    {
        using var recipient = HybridKem.GenerateKeyPair();
        var envelope = HybridEnvelope.Seal(recipient.PublicKey, Plaintext);
        var recovered = HybridEnvelope.Open(recipient.PrivateKey, envelope);
        Assert.Equal(Plaintext, recovered);
    }

    [Fact]
    public void EnvelopeSize_IsPlaintextPlusOverhead()
    {
        using var recipient = HybridKem.GenerateKeyPair();
        var envelope = HybridEnvelope.Seal(recipient.PublicKey, Plaintext);
        Assert.Equal(HybridEnvelope.OverheadBytes + Plaintext.Length, envelope.Length);
    }

    [Fact]
    public void Seal_TwoCalls_ProduceDifferentEnvelopes()
    {
        using var recipient = HybridKem.GenerateKeyPair();
        var a = HybridEnvelope.Seal(recipient.PublicKey, Plaintext);
        var b = HybridEnvelope.Seal(recipient.PublicKey, Plaintext);
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Open_WrongPrivateKey_ThrowsAuthenticationFailure()
    {
        using var alice = HybridKem.GenerateKeyPair();
        using var bob = HybridKem.GenerateKeyPair();
        var envelope = HybridEnvelope.Seal(alice.PublicKey, Plaintext);
        Assert.Throws<AuthenticationTagMismatchException>(() =>
            HybridEnvelope.Open(bob.PrivateKey, envelope));
    }

    [Fact]
    public void Open_TamperedCiphertext_Throws()
    {
        using var recipient = HybridKem.GenerateKeyPair();
        var envelope = HybridEnvelope.Seal(recipient.PublicKey, Plaintext);
        envelope[envelope.Length - 1] ^= 0xFF; // tamper inside AEAD ciphertext
        Assert.Throws<AuthenticationTagMismatchException>(() =>
            HybridEnvelope.Open(recipient.PrivateKey, envelope));
    }

    [Fact]
    public void Open_TamperedKemCiphertext_Throws()
    {
        using var recipient = HybridKem.GenerateKeyPair();
        var envelope = HybridEnvelope.Seal(recipient.PublicKey, Plaintext);
        envelope[100] ^= 0xFF; // tamper inside KEM ciphertext portion
        Assert.Throws<AuthenticationTagMismatchException>(() =>
            HybridEnvelope.Open(recipient.PrivateKey, envelope));
    }

    [Fact]
    public void Open_WrongVersion_ThrowsTypedException()
    {
        using var recipient = HybridKem.GenerateKeyPair();
        var envelope = HybridEnvelope.Seal(recipient.PublicKey, Plaintext);
        envelope[0] = 0xEE;
        var ex = Assert.Throws<PostQuantumHybridException>(() =>
            HybridEnvelope.Open(recipient.PrivateKey, envelope));
        Assert.Equal(HybridFailureReason.UnsupportedAlgorithmId, ex.Reason);
    }

    [Fact]
    public void Open_TooShort_ThrowsTypedException()
    {
        using var recipient = HybridKem.GenerateKeyPair();
        var ex = Assert.Throws<PostQuantumHybridException>(() =>
            HybridEnvelope.Open(recipient.PrivateKey, new byte[10]));
        Assert.Equal(HybridFailureReason.InvalidLength, ex.Reason);
    }

    [Fact]
    public void Seal_EmptyPlaintext_RoundTrips()
    {
        using var recipient = HybridKem.GenerateKeyPair();
        var envelope = HybridEnvelope.Seal(recipient.PublicKey, ReadOnlySpan<byte>.Empty);
        var recovered = HybridEnvelope.Open(recipient.PrivateKey, envelope);
        Assert.Equal(Array.Empty<byte>(), recovered);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(1024)]
    [InlineData(65_536)]
    public void Seal_VaryingSizes_RoundTrip(int size)
    {
        using var recipient = HybridKem.GenerateKeyPair();
        var plaintext = new byte[size];
        new Random(size).NextBytes(plaintext);

        var envelope = HybridEnvelope.Seal(recipient.PublicKey, plaintext);
        var recovered = HybridEnvelope.Open(recipient.PrivateKey, envelope);
        Assert.Equal(plaintext, recovered);
    }

    [Fact]
    public void Seal_NullRecipient_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            HybridEnvelope.Seal(null!, ReadOnlySpan<byte>.Empty));
    }
}
