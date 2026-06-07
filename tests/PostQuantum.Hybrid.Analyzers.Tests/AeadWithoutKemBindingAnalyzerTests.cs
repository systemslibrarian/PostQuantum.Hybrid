using Microsoft.CodeAnalysis;
using Xunit;

namespace PostQuantum.Hybrid.Analyzers.Tests;

public class AeadWithoutKemBindingAnalyzerTests
{
    private static readonly MetadataReference PqhReference =
        MetadataReference.CreateFromFile(typeof(global::PostQuantum.Hybrid.HybridKem).Assembly.Location);

    private static async Task<IReadOnlyList<Diagnostic>> RunAsync(string code) =>
        await AnalyzerTestHarness.AnalyzeAsync(
            new AeadWithoutKemBindingAnalyzer(),
            code,
            PqhReference);

    [Fact]
    public async Task EncryptWithoutAad_InHybridFlow_FlagsPqh005()
    {
        var diags = await RunAsync("""
            using PostQuantum.Hybrid;
            using System.Security.Cryptography;
            class C
            {
                void M(HybridKemPublicKey pub, byte[] aesKey, byte[] nonce, byte[] pt, byte[] ct, byte[] tag)
                {
                    using var enc = HybridKem.Encapsulate(pub);
                    using var aes = new AesGcm(aesKey, 16);
                    aes.Encrypt(nonce, pt, ct, tag);
                }
            }
            """);
        var single = Assert.Single(diags);
        Assert.Equal("PQH005", single.Id);
    }

    [Fact]
    public async Task EncryptWithAadByName_InHybridFlow_NoWarning()
    {
        var diags = await RunAsync("""
            using PostQuantum.Hybrid;
            using System.Security.Cryptography;
            class C
            {
                void M(HybridKemPublicKey pub, byte[] aesKey, byte[] nonce, byte[] pt, byte[] ct, byte[] tag, byte[] aad)
                {
                    using var enc = HybridKem.Encapsulate(pub);
                    using var aes = new AesGcm(aesKey, 16);
                    aes.Encrypt(nonce, pt, ct, tag, associatedData: aad);
                }
            }
            """);
        Assert.Empty(diags);
    }

    [Fact]
    public async Task EncryptWithAadPositional_InHybridFlow_NoWarning()
    {
        var diags = await RunAsync("""
            using PostQuantum.Hybrid;
            using System.Security.Cryptography;
            class C
            {
                void M(HybridKemPublicKey pub, byte[] aesKey, byte[] nonce, byte[] pt, byte[] ct, byte[] tag, byte[] aad)
                {
                    using var enc = HybridKem.Encapsulate(pub);
                    using var aes = new AesGcm(aesKey, 16);
                    aes.Encrypt(nonce, pt, ct, tag, aad);
                }
            }
            """);
        Assert.Empty(diags);
    }

    [Fact]
    public async Task EncryptOutsideHybridFlow_NoWarning()
    {
        var diags = await RunAsync("""
            using System.Security.Cryptography;
            class C
            {
                void M(byte[] aesKey, byte[] nonce, byte[] pt, byte[] ct, byte[] tag)
                {
                    using var aes = new AesGcm(aesKey, 16);
                    aes.Encrypt(nonce, pt, ct, tag);
                }
            }
            """);
        Assert.Empty(diags);
    }

    [Fact]
    public async Task DecryptWithoutAad_InHybridFlow_FlagsPqh005()
    {
        var diags = await RunAsync("""
            using PostQuantum.Hybrid;
            using System.Security.Cryptography;
            class C
            {
                void M(HybridKemPrivateKey priv, HybridKemCiphertext kemCt, byte[] aesKey, byte[] nonce, byte[] ct, byte[] tag, byte[] pt)
                {
                    var ss = HybridKem.Decapsulate(priv, kemCt);
                    using var aes = new AesGcm(aesKey, 16);
                    aes.Decrypt(nonce, ct, tag, pt);
                }
            }
            """);
        var single = Assert.Single(diags);
        Assert.Equal("PQH005", single.Id);
    }
}
