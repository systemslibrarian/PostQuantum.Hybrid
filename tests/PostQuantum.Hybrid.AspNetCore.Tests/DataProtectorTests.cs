using Microsoft.AspNetCore.DataProtection;
using PostQuantum.Hybrid;
using PostQuantum.Hybrid.AspNetCore;
using Xunit;

namespace PostQuantum.Hybrid.AspNetCore.Tests;

public class DataProtectorTests
{
    private static FakeKemProvider NewProvider()
    {
        return new FakeKemProvider(HybridKem.GenerateKeyPair());
    }

    [Fact]
    public void Protect_Unprotect_RoundTrip()
    {
        using var provider = NewProvider();
        var p = new HybridEnvelopeDataProtector(provider, "myapp.v1");

        var plaintext = "hello"u8.ToArray();
        var protectedData = p.Protect(plaintext);
        var unprotected = p.Unprotect(protectedData);
        Assert.Equal(plaintext, unprotected);
    }

    [Fact]
    public void Protect_TwoCalls_ProduceDifferentBlobs()
    {
        using var provider = NewProvider();
        var p = new HybridEnvelopeDataProtector(provider, "myapp.v1");
        var plaintext = "deterministic input"u8.ToArray();

        var a = p.Protect(plaintext);
        var b = p.Protect(plaintext);
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void CreateProtector_DifferentPurpose_CannotUnprotectOther()
    {
        using var provider = NewProvider();
        IDataProtector parent = new HybridEnvelopeDataProtector(provider, "root");
        var purposeA = parent.CreateProtector("payments");
        var purposeB = parent.CreateProtector("audit");

        var data = "x"u8.ToArray();
        var protectedByA = purposeA.Protect(data);

        Assert.Throws<System.Security.Cryptography.AuthenticationTagMismatchException>(
            () => purposeB.Unprotect(protectedByA));
    }

    [Fact]
    public void CreateProtector_SamePurpose_CanUnprotect()
    {
        using var provider = NewProvider();
        IDataProtector parent = new HybridEnvelopeDataProtector(provider, "root");
        var a = parent.CreateProtector("payments");
        var b = parent.CreateProtector("payments");

        var data = "x"u8.ToArray();
        Assert.Equal(data, b.Unprotect(a.Protect(data)));
    }

    [Fact]
    public void Unprotect_TamperedBlob_Throws()
    {
        using var provider = NewProvider();
        var p = new HybridEnvelopeDataProtector(provider, "myapp.v1");

        var protectedData = p.Protect("payload"u8.ToArray());
        protectedData[protectedData.Length - 5] ^= 0xFF;
        Assert.Throws<System.Security.Cryptography.AuthenticationTagMismatchException>(
            () => p.Unprotect(protectedData));
    }

    [Fact]
    public void Unprotect_WrongPrivateKey_Throws()
    {
        using var alice = NewProvider();
        using var bob = NewProvider();
        var aliceProtector = new HybridEnvelopeDataProtector(alice, "root");
        var bobProtector = new HybridEnvelopeDataProtector(bob, "root");

        var protectedByAlice = aliceProtector.Protect("p"u8.ToArray());
        Assert.Throws<System.Security.Cryptography.AuthenticationTagMismatchException>(
            () => bobProtector.Unprotect(protectedByAlice));
    }

    private sealed class FakeKemProvider : IHybridKemKeyProvider, IDisposable
    {
        public HybridKemPublicKey PublicKey { get; }
        public HybridKemPrivateKey PrivateKey { get; }

        public FakeKemProvider(HybridKemKeyPair pair)
        {
            PublicKey = pair.PublicKey;
            PrivateKey = pair.PrivateKey;
        }

        public void Dispose() => PrivateKey.Dispose();
    }
}
