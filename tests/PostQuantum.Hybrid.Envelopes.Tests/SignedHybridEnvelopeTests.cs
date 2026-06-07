using System.Security.Cryptography;
using System.Text;
using PostQuantum.Hybrid;
using PostQuantum.Hybrid.Envelopes;
using Xunit;

namespace PostQuantum.Hybrid.Envelopes.Tests;

public class SignedHybridEnvelopeTests
{
    private static readonly byte[] Plaintext =
        Encoding.UTF8.GetBytes("authenticated payload");

    [Fact]
    public void Seal_Open_RoundTrip()
    {
        using var sender = HybridSignature.GenerateKeyPair();
        using var recipient = HybridKem.GenerateKeyPair();

        var envelope = SignedHybridEnvelope.Seal(sender.PrivateKey, recipient.PublicKey, Plaintext);
        var recovered = SignedHybridEnvelope.Open(sender.PublicKey, recipient.PrivateKey, envelope);
        Assert.Equal(Plaintext, recovered);
    }

    [Fact]
    public void EnvelopeSize_IsPlaintextPlusOverhead()
    {
        using var sender = HybridSignature.GenerateKeyPair();
        using var recipient = HybridKem.GenerateKeyPair();

        var envelope = SignedHybridEnvelope.Seal(sender.PrivateKey, recipient.PublicKey, Plaintext);
        Assert.Equal(SignedHybridEnvelope.OverheadBytes + Plaintext.Length, envelope.Length);
    }

    [Fact]
    public void Open_WrongSenderKey_ThrowsCryptographicException()
    {
        using var alice = HybridSignature.GenerateKeyPair();
        using var eve = HybridSignature.GenerateKeyPair();
        using var recipient = HybridKem.GenerateKeyPair();

        var envelope = SignedHybridEnvelope.Seal(alice.PrivateKey, recipient.PublicKey, Plaintext);
        Assert.Throws<CryptographicException>(() =>
            SignedHybridEnvelope.Open(eve.PublicKey, recipient.PrivateKey, envelope));
    }

    [Fact]
    public void Open_TamperedSignature_ThrowsBeforeDecapsulation()
    {
        using var sender = HybridSignature.GenerateKeyPair();
        using var recipient = HybridKem.GenerateKeyPair();

        var envelope = SignedHybridEnvelope.Seal(sender.PrivateKey, recipient.PublicKey, Plaintext);
        envelope[envelope.Length - 50] ^= 0xFF; // inside the signature
        Assert.Throws<CryptographicException>(() =>
            SignedHybridEnvelope.Open(sender.PublicKey, recipient.PrivateKey, envelope));
    }

    [Fact]
    public void Open_TamperedInner_ThrowsAtSignatureCheck()
    {
        using var sender = HybridSignature.GenerateKeyPair();
        using var recipient = HybridKem.GenerateKeyPair();

        var envelope = SignedHybridEnvelope.Seal(sender.PrivateKey, recipient.PublicKey, Plaintext);
        envelope[200] ^= 0xFF; // inside the KEM ciphertext portion of the inner envelope
        Assert.Throws<CryptographicException>(() =>
            SignedHybridEnvelope.Open(sender.PublicKey, recipient.PrivateKey, envelope));
    }

    [Fact]
    public void Open_TooShort_Throws()
    {
        using var sender = HybridSignature.GenerateKeyPair();
        using var recipient = HybridKem.GenerateKeyPair();
        var ex = Assert.Throws<PostQuantumHybridException>(() =>
            SignedHybridEnvelope.Open(sender.PublicKey, recipient.PrivateKey, new byte[10]));
        Assert.Equal(HybridFailureReason.InvalidLength, ex.Reason);
    }

    [Fact]
    public void EveCannotForgeEnvelopeBetweenAliceAndBob()
    {
        // Alice signs envelopes; Bob is the recipient. Eve tries to forge.
        using var alice = HybridSignature.GenerateKeyPair();
        using var bob = HybridKem.GenerateKeyPair();
        using var eve = HybridSignature.GenerateKeyPair();

        // Eve seals against Bob's KEM but signs with HER OWN key.
        var forgedByEve = SignedHybridEnvelope.Seal(eve.PrivateKey, bob.PublicKey, Plaintext);

        // Bob expects Alice's signature. Open must fail.
        Assert.Throws<CryptographicException>(() =>
            SignedHybridEnvelope.Open(alice.PublicKey, bob.PrivateKey, forgedByEve));
    }
}
