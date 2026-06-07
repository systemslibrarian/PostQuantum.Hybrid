using Xunit;

namespace PostQuantum.Hybrid.Tests;

/// <summary>
/// The library's static APIs must be safe to call concurrently from many
/// threads, as long as each thread brings its own private-key instance
/// (sharing a private-key instance across threads is undefined).
/// </summary>
public class ConcurrencyTests
{
    [Fact]
    public void GenerateKeyPair_OnManyThreadsConcurrently_AllSucceed()
    {
        Parallel.For(0, 50, _ =>
        {
            using var p = HybridKem.GenerateKeyPair();
            Assert.Equal(1217, p.PublicKey.Export().Length);
        });
    }

    [Fact]
    public void SignAndVerify_OnManyThreadsConcurrently_AllSucceed()
    {
        Parallel.For(0, 50, i =>
        {
            using var p = HybridSignature.GenerateKeyPair();
            var msg = BitConverter.GetBytes(i);
            var sig = HybridSignature.Sign(p.PrivateKey, msg);
            Assert.True(HybridSignature.Verify(p.PublicKey, msg, sig));
        });
    }

    [Fact]
    public void EncapsulateAgainstSharedPublicKey_OnManyThreads_AllSucceed()
    {
        // A public key is safe to share across threads — only private keys
        // and disposable handles are thread-affine.
        using var pair = HybridKem.GenerateKeyPair();
        var publicKey = pair.PublicKey;

        Parallel.For(0, 50, _ =>
        {
            using var enc = HybridKem.Encapsulate(publicKey);
            Assert.Equal(32, enc.SharedSecret.Length);
            Assert.Equal(1121, enc.Ciphertext.ToBytes().Length);
        });
    }
}
