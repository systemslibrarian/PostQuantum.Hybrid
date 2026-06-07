using System.Text;
using Xunit;

namespace PostQuantum.Hybrid.Tests;

public class SignatureEdgeCaseTests
{
    [Fact]
    public void Sign_EmptyMessage_ProducesVerifiableSignature()
    {
        using var pair = HybridSignature.GenerateKeyPair();
        var sig = HybridSignature.Sign(pair.PrivateKey, ReadOnlySpan<byte>.Empty);
        Assert.True(HybridSignature.Verify(pair.PublicKey, ReadOnlySpan<byte>.Empty, sig));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(16)]
    [InlineData(1024)]
    [InlineData(65_536)]
    [InlineData(1_048_576)]
    public void Sign_VaryingMessageSizes_RoundTrip(int messageLength)
    {
        using var pair = HybridSignature.GenerateKeyPair();
        var message = new byte[messageLength];
        new Random(messageLength).NextBytes(message);

        var sig = HybridSignature.Sign(pair.PrivateKey, message);
        Assert.True(HybridSignature.Verify(pair.PublicKey, message, sig));
    }

    [Fact]
    public void Verify_EmptyMessageWithWrongMessage_ReturnsFalse()
    {
        using var pair = HybridSignature.GenerateKeyPair();
        var sig = HybridSignature.Sign(pair.PrivateKey, ReadOnlySpan<byte>.Empty);
        Assert.False(HybridSignature.Verify(pair.PublicKey, "x"u8.ToArray(), sig));
    }

    [Fact]
    public void Sign_NullPrivateKey_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => HybridSignature.Sign(null!, new byte[1]));
    }

    [Fact]
    public void Verify_NullPublicKey_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => HybridSignature.Verify(null!, new byte[1], new byte[3374]));
    }

    [Fact]
    public void Sign_OnDisposedPrivateKey_Throws()
    {
        var pair = HybridSignature.GenerateKeyPair();
        pair.PrivateKey.Dispose();
        Assert.Throws<ObjectDisposedException>(() => HybridSignature.Sign(pair.PrivateKey, new byte[1]));
    }

    [Fact]
    public void TwentyFreshKeyPairs_SignAndVerifyIndependently()
    {
        var msg = "fresh key per iteration"u8.ToArray();
        for (var i = 0; i < 20; i++)
        {
            using var pair = HybridSignature.GenerateKeyPair();
            var sig = HybridSignature.Sign(pair.PrivateKey, msg);
            Assert.True(HybridSignature.Verify(pair.PublicKey, msg, sig));
        }
    }

    [Fact]
    public void SignatureBytes_ContainBothComponents()
    {
        // Sanity: layout is algId(1) + ed25519(64) + mldsa65(3309) = 3374.
        using var pair = HybridSignature.GenerateKeyPair();
        var sig = HybridSignature.Sign(pair.PrivateKey, new byte[1]);
        Assert.Equal(3374, sig.Length);

        // Tampering only with the classical half (bytes 1..64) -> verify false.
        var t1 = (byte[])sig.Clone();
        t1[10] ^= 0xFF;
        Assert.False(HybridSignature.Verify(pair.PublicKey, new byte[1], t1));

        // Tampering only with the PQ half (bytes 65..3373) -> verify false.
        var t2 = (byte[])sig.Clone();
        t2[2000] ^= 0xFF;
        Assert.False(HybridSignature.Verify(pair.PublicKey, new byte[1], t2));
    }

    [Fact]
    public void UnicodeMessage_RoundTrips()
    {
        using var pair = HybridSignature.GenerateKeyPair();
        var msg = Encoding.UTF8.GetBytes("こんにちは 🔐 post-quantum 你好 שלום");
        var sig = HybridSignature.Sign(pair.PrivateKey, msg);
        Assert.True(HybridSignature.Verify(pair.PublicKey, msg, sig));
    }
}
