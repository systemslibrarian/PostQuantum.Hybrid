using Microsoft.CodeAnalysis;
using Xunit;

namespace PostQuantum.Hybrid.Analyzers.Tests;

public class HybridDisposeAnalyzerTests
{
    private static readonly MetadataReference PqhReference =
        MetadataReference.CreateFromFile(typeof(global::PostQuantum.Hybrid.HybridKem).Assembly.Location);

    private static async Task<IReadOnlyList<Diagnostic>> RunAsync(string code)
    {
        return await AnalyzerTestHarness.AnalyzeAsync(
            new HybridDisposeAnalyzer(),
            code,
            PqhReference);
    }

    [Fact]
    public async Task UsingDeclaration_NoWarning()
    {
        var diags = await RunAsync("""
            using PostQuantum.Hybrid;
            class C
            {
                void M()
                {
                    using var pair = HybridKem.GenerateKeyPair();
                }
            }
            """);
        Assert.Empty(diags);
    }

    [Fact]
    public async Task UsingStatement_NoWarning()
    {
        var diags = await RunAsync("""
            using PostQuantum.Hybrid;
            class C
            {
                void M()
                {
                    using (var pair = HybridKem.GenerateKeyPair()) { }
                }
            }
            """);
        Assert.Empty(diags);
    }

    [Fact]
    public async Task PlainVar_HybridKemKeyPair_FlagsPqh001()
    {
        var diags = await RunAsync("""
            using PostQuantum.Hybrid;
            class C
            {
                void M()
                {
                    var pair = HybridKem.GenerateKeyPair();
                }
            }
            """);
        var single = Assert.Single(diags);
        Assert.Equal("PQH001", single.Id);
        Assert.Equal(DiagnosticSeverity.Warning, single.Severity);
        Assert.Contains("pair", single.GetMessage());
    }

    [Fact]
    public async Task PlainVar_HybridSignatureKeyPair_FlagsPqh001()
    {
        var diags = await RunAsync("""
            using PostQuantum.Hybrid;
            class C
            {
                void M()
                {
                    var pair = HybridSignature.GenerateKeyPair();
                }
            }
            """);
        var single = Assert.Single(diags);
        Assert.Equal("PQH001", single.Id);
    }

    [Fact]
    public async Task PlainVar_EncapsulationResult_FlagsPqh001()
    {
        var diags = await RunAsync("""
            using PostQuantum.Hybrid;
            class C
            {
                void M(HybridKemPublicKey pub)
                {
                    var enc = HybridKem.Encapsulate(pub);
                }
            }
            """);
        var single = Assert.Single(diags);
        Assert.Equal("PQH001", single.Id);
        Assert.Contains("enc", single.GetMessage());
    }

    [Fact]
    public async Task UnrelatedType_NoWarning()
    {
        var diags = await RunAsync("""
            class C
            {
                void M()
                {
                    var s = new System.IO.MemoryStream();
                }
            }
            """);
        Assert.Empty(diags);
    }

    [Fact]
    public async Task PublicKey_NotFlagged()
    {
        // Public keys are not disposable in our model.
        var diags = await RunAsync("""
            using PostQuantum.Hybrid;
            class C
            {
                void M(byte[] bytes)
                {
                    var pub = HybridKemPublicKey.Import(bytes);
                }
            }
            """);
        Assert.Empty(diags);
    }

    [Fact]
    public async Task PrivateKey_ImportPem_AlsoFlagged()
    {
        var diags = await RunAsync("""
            using PostQuantum.Hybrid;
            class C
            {
                void M(string pem)
                {
                    var priv = HybridKemPrivateKey.ImportPem(pem);
                }
            }
            """);
        var single = Assert.Single(diags);
        Assert.Equal("PQH001", single.Id);
    }
}
