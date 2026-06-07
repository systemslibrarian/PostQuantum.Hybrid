using Microsoft.CodeAnalysis;
using Xunit;

namespace PostQuantum.Hybrid.Analyzers.Tests;

public class HkdfWrapSharedSecretCodeFixTests
{
    private static readonly MetadataReference PqhReference =
        MetadataReference.CreateFromFile(typeof(global::PostQuantum.Hybrid.HybridKem).Assembly.Location);

    private static Task<string> ApplyAsync(string code) =>
        CodeFixTestHarness.ApplyFixAsync(
            new SharedSecretWithoutHkdfAnalyzer(),
            new HkdfWrapSharedSecretCodeFix(),
            "PQH002",
            code,
            PqhReference);

    [Fact]
    public async Task DirectSharedSecret_WrapsWithHkdfDeriveKey()
    {
        var fixedCode = await ApplyAsync("""
            using PostQuantum.Hybrid;
            using System.Security.Cryptography;
            class C
            {
                void M(HybridKemEncapsulationResult enc)
                {
                    var aes = new AesGcm(enc.SharedSecret, 16);
                }
            }
            """);

        Assert.Contains("HKDF.DeriveKey", fixedCode);
        Assert.Contains("HashAlgorithmName.SHA256", fixedCode);
        Assert.Contains("enc.SharedSecret", fixedCode);
        Assert.Contains("salt: null", fixedCode);
        Assert.Contains("info:", fixedCode);
        Assert.DoesNotContain("new AesGcm(enc.SharedSecret,", fixedCode);
    }

    [Fact]
    public async Task SharedSecretAsSpan_StripsAsSpanAndWraps()
    {
        var fixedCode = await ApplyAsync("""
            using PostQuantum.Hybrid;
            using System.Security.Cryptography;
            class C
            {
                void M(HybridKemEncapsulationResult enc)
                {
                    var hmac = new HMACSHA256(enc.SharedSecret.AsSpan().ToArray());
                }
            }
            """);

        Assert.Contains("HKDF.DeriveKey", fixedCode);
        // AsSpan/ToArray wrappers should be stripped; the inner SharedSecret access feeds DeriveKey.
        Assert.DoesNotContain(".AsSpan()", fixedCode);
    }
}
