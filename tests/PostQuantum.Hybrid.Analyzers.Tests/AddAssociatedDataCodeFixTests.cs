using Microsoft.CodeAnalysis;
using Xunit;

namespace PostQuantum.Hybrid.Analyzers.Tests;

public class AddAssociatedDataCodeFixTests
{
    private static readonly MetadataReference PqhReference =
        MetadataReference.CreateFromFile(typeof(global::PostQuantum.Hybrid.HybridKem).Assembly.Location);

    private static Task<string> ApplyAsync(string code) =>
        CodeFixTestHarness.ApplyFixAsync(
            new AeadWithoutKemBindingAnalyzer(),
            new AddAssociatedDataCodeFix(),
            "PQH005",
            code,
            PqhReference);

    [Fact]
    public async Task EncapFlow_UsesEncapsulationResultCiphertext()
    {
        var fixedCode = await ApplyAsync("""
            using PostQuantum.Hybrid;
            using System.Security.Cryptography;
            class C
            {
                void M(HybridKemPublicKey pub, byte[] plaintext, byte[] nonce, byte[] ct, byte[] tag)
                {
                    using var enc = HybridKem.Encapsulate(pub);
                    var aes = new AesGcm(new byte[32], 16);
                    aes.Encrypt(nonce, plaintext, ct, tag);
                }
            }
            """);

        Assert.Contains("associatedData: enc.Ciphertext", fixedCode);
    }

    [Fact]
    public async Task DecapFlow_UsesDecapsulateCiphertextArg()
    {
        var fixedCode = await ApplyAsync("""
            using PostQuantum.Hybrid;
            using System.Security.Cryptography;
            class C
            {
                void M(HybridKemPrivateKey priv, byte[] kemCipher, byte[] nonce, byte[] ct, byte[] tag, byte[] pt)
                {
                    var ss = HybridKem.Decapsulate(priv, kemCipher);
                    var aes = new AesGcm(new byte[32], 16);
                    aes.Decrypt(nonce, ct, tag, pt);
                }
            }
            """);

        Assert.Contains("associatedData: kemCipher", fixedCode);
    }

    [Fact]
    public async Task UnknownContext_FallsBackToTodoPlaceholder()
    {
        var fixedCode = await ApplyAsync("""
            using PostQuantum.Hybrid;
            using System.Security.Cryptography;
            class C
            {
                void M(HybridKemPrivateKey priv, byte[] nonce, byte[] ct, byte[] tag, byte[] pt)
                {
                    // The analyzer fires because the method body invokes HybridKem.Decapsulate,
                    // but with a single positional arg the code-fix can't infer the ciphertext.
                    HybridKem.Decapsulate(priv, default!);
                    var aes = new AesGcm(new byte[32], 16);
                    aes.Decrypt(nonce, ct, tag, pt);
                }
            }
            """);

        Assert.Contains("associatedData:", fixedCode);
    }
}
