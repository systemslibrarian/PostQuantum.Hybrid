using Microsoft.CodeAnalysis;
using Xunit;

namespace PostQuantum.Hybrid.Analyzers.Tests;

public class IgnoredVerifyResultAnalyzerTests
{
    private static readonly MetadataReference PqhReference =
        MetadataReference.CreateFromFile(typeof(global::PostQuantum.Hybrid.HybridKem).Assembly.Location);

    private static async Task<IReadOnlyList<Diagnostic>> RunAsync(string code)
    {
        return await AnalyzerTestHarness.AnalyzeAsync(
            new IgnoredVerifyResultAnalyzer(),
            code,
            PqhReference);
    }

    [Fact]
    public async Task DiscardedReturn_FlagsPqh004()
    {
        var diags = await RunAsync("""
            using PostQuantum.Hybrid;
            class C
            {
                void M(HybridSignaturePublicKey pub, byte[] msg, byte[] sig)
                {
                    HybridSignature.Verify(pub, msg, sig);
                }
            }
            """);
        var single = Assert.Single(diags);
        Assert.Equal("PQH004", single.Id);
        Assert.Equal(DiagnosticSeverity.Warning, single.Severity);
    }

    [Fact]
    public async Task UnderscoreDiscard_FlagsPqh004()
    {
        var diags = await RunAsync("""
            using PostQuantum.Hybrid;
            class C
            {
                void M(HybridSignaturePublicKey pub, byte[] msg, byte[] sig)
                {
                    _ = HybridSignature.Verify(pub, msg, sig);
                }
            }
            """);
        var single = Assert.Single(diags);
        Assert.Equal("PQH004", single.Id);
    }

    [Fact]
    public async Task IfStatement_NoWarning()
    {
        var diags = await RunAsync("""
            using PostQuantum.Hybrid;
            using System.Security.Cryptography;
            class C
            {
                void M(HybridSignaturePublicKey pub, byte[] msg, byte[] sig)
                {
                    if (!HybridSignature.Verify(pub, msg, sig))
                    {
                        throw new CryptographicException();
                    }
                }
            }
            """);
        Assert.Empty(diags);
    }

    [Fact]
    public async Task LocalAssignment_NoWarning()
    {
        var diags = await RunAsync("""
            using PostQuantum.Hybrid;
            class C
            {
                void M(HybridSignaturePublicKey pub, byte[] msg, byte[] sig)
                {
                    var ok = HybridSignature.Verify(pub, msg, sig);
                    System.Console.WriteLine(ok);
                }
            }
            """);
        Assert.Empty(diags);
    }

    [Fact]
    public async Task ReturnExpression_NoWarning()
    {
        var diags = await RunAsync("""
            using PostQuantum.Hybrid;
            class C
            {
                bool M(HybridSignaturePublicKey pub, byte[] msg, byte[] sig)
                    => HybridSignature.Verify(pub, msg, sig);
            }
            """);
        Assert.Empty(diags);
    }

    [Fact]
    public async Task UnrelatedVerifyMethod_NoWarning()
    {
        var diags = await RunAsync("""
            class C
            {
                bool Verify(byte[] x) => true;
                void M()
                {
                    Verify(System.Array.Empty<byte>());
                }
            }
            """);
        Assert.Empty(diags);
    }
}
