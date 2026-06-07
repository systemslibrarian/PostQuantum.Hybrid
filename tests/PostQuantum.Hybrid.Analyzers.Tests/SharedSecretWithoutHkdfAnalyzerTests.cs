using Microsoft.CodeAnalysis;
using Xunit;

namespace PostQuantum.Hybrid.Analyzers.Tests;

public class SharedSecretWithoutHkdfAnalyzerTests
{
    private static readonly MetadataReference PqhReference =
        MetadataReference.CreateFromFile(typeof(global::PostQuantum.Hybrid.HybridKem).Assembly.Location);

    private static async Task<IReadOnlyList<Diagnostic>> RunAsync(string code) =>
        await AnalyzerTestHarness.AnalyzeAsync(
            new SharedSecretWithoutHkdfAnalyzer(),
            code,
            PqhReference);

    [Fact]
    public async Task AesGcm_DirectSharedSecret_FlagsPqh002()
    {
        var diags = await RunAsync("""
            using PostQuantum.Hybrid;
            using System.Security.Cryptography;
            class C
            {
                void M(HybridKemEncapsulationResult enc)
                {
                    using var aes = new AesGcm(enc.SharedSecret, 16);
                }
            }
            """);
        var single = Assert.Single(diags);
        Assert.Equal("PQH002", single.Id);
    }

    [Fact]
    public async Task HmacSha256_DirectSharedSecret_FlagsPqh002()
    {
        var diags = await RunAsync("""
            using PostQuantum.Hybrid;
            using System.Security.Cryptography;
            class C
            {
                void M(HybridKemEncapsulationResult enc)
                {
                    using var h = new HMACSHA256(enc.SharedSecret);
                }
            }
            """);
        var single = Assert.Single(diags);
        Assert.Equal("PQH002", single.Id);
    }

    [Fact]
    public async Task DerivedKeyViaHkdf_NoWarning()
    {
        var diags = await RunAsync("""
            using PostQuantum.Hybrid;
            using System.Security.Cryptography;
            class C
            {
                void M(HybridKemEncapsulationResult enc)
                {
                    var key = new byte[32];
                    HKDF.Expand(HashAlgorithmName.SHA256, enc.SharedSecret, key, info: System.Text.Encoding.ASCII.GetBytes("ctx"));
                    using var aes = new AesGcm(key, 16);
                }
            }
            """);
        Assert.Empty(diags);
    }

    [Fact]
    public async Task UnrelatedAesKey_NoWarning()
    {
        var diags = await RunAsync("""
            using System.Security.Cryptography;
            class C
            {
                void M(byte[] someKey)
                {
                    using var aes = new AesGcm(someKey, 16);
                }
            }
            """);
        Assert.Empty(diags);
    }

    [Fact]
    public async Task AsSpanOnSharedSecret_AlsoFlagged()
    {
        var diags = await RunAsync("""
            using PostQuantum.Hybrid;
            using System.Security.Cryptography;
            class C
            {
                void M(HybridKemEncapsulationResult enc)
                {
                    using var aes = new AesGcm(enc.SharedSecret.AsSpan(), 16);
                }
            }
            """);
        var single = Assert.Single(diags);
        Assert.Equal("PQH002", single.Id);
    }
}
