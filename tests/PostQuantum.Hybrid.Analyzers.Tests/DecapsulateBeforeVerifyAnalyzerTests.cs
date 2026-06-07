using Microsoft.CodeAnalysis;
using Xunit;

namespace PostQuantum.Hybrid.Analyzers.Tests;

public class DecapsulateBeforeVerifyAnalyzerTests
{
    private static readonly MetadataReference PqhReference =
        MetadataReference.CreateFromFile(typeof(global::PostQuantum.Hybrid.HybridKem).Assembly.Location);

    private static async Task<IReadOnlyList<Diagnostic>> RunAsync(string code) =>
        await AnalyzerTestHarness.AnalyzeAsync(
            new DecapsulateBeforeVerifyAnalyzer(),
            code,
            PqhReference);

    [Fact]
    public async Task DecapsulateBeforeVerify_FlagsPqh003()
    {
        var diags = await RunAsync("""
            using PostQuantum.Hybrid;
            class C
            {
                void M(HybridKemPrivateKey priv, HybridKemCiphertext ct,
                       HybridSignaturePublicKey pub, byte[] msg, byte[] sig)
                {
                    var ss = HybridKem.Decapsulate(priv, ct);
                    var ok = HybridSignature.Verify(pub, msg, sig);
                }
            }
            """);
        var single = Assert.Single(diags);
        Assert.Equal("PQH003", single.Id);
    }

    [Fact]
    public async Task VerifyBeforeDecapsulate_NoWarning()
    {
        var diags = await RunAsync("""
            using PostQuantum.Hybrid;
            using System.Security.Cryptography;
            class C
            {
                void M(HybridKemPrivateKey priv, HybridKemCiphertext ct,
                       HybridSignaturePublicKey pub, byte[] msg, byte[] sig)
                {
                    if (!HybridSignature.Verify(pub, msg, sig))
                    {
                        throw new CryptographicException();
                    }
                    var ss = HybridKem.Decapsulate(priv, ct);
                }
            }
            """);
        Assert.Empty(diags);
    }

    [Fact]
    public async Task DecapsulateOnly_NoWarning()
    {
        var diags = await RunAsync("""
            using PostQuantum.Hybrid;
            class C
            {
                void M(HybridKemPrivateKey priv, HybridKemCiphertext ct)
                {
                    var ss = HybridKem.Decapsulate(priv, ct);
                }
            }
            """);
        Assert.Empty(diags);
    }

    [Fact]
    public async Task VerifyOnly_NoWarning()
    {
        var diags = await RunAsync("""
            using PostQuantum.Hybrid;
            class C
            {
                void M(HybridSignaturePublicKey pub, byte[] msg, byte[] sig)
                {
                    var ok = HybridSignature.Verify(pub, msg, sig);
                }
            }
            """);
        Assert.Empty(diags);
    }
}
