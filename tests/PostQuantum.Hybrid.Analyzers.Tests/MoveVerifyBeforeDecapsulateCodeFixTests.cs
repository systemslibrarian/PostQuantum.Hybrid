using Microsoft.CodeAnalysis;
using Xunit;

namespace PostQuantum.Hybrid.Analyzers.Tests;

public class MoveVerifyBeforeDecapsulateCodeFixTests
{
    private static readonly MetadataReference PqhReference =
        MetadataReference.CreateFromFile(typeof(global::PostQuantum.Hybrid.HybridKem).Assembly.Location);

    private static Task<string> ApplyAsync(string code) =>
        CodeFixTestHarness.ApplyFixAsync(
            new DecapsulateBeforeVerifyAnalyzer(),
            new MoveVerifyBeforeDecapsulateCodeFix(),
            "PQH003",
            code,
            PqhReference);

    [Fact]
    public async Task DecapBeforeVerifyInSameBlock_ReordersVerifyAbove()
    {
        var fixedCode = await ApplyAsync("""
            using PostQuantum.Hybrid;
            using System.Security.Cryptography;
            class C
            {
                void M(HybridKemPrivateKey kemPriv, byte[] kemCt,
                       HybridSignaturePublicKey sigPub, byte[] msg, byte[] sig)
                {
                    var ss = HybridKem.Decapsulate(kemPriv, kemCt);
                    if (!HybridSignature.Verify(sigPub, msg, sig))
                    {
                        throw new CryptographicException();
                    }
                }
            }
            """);

        var decapIndex = fixedCode.IndexOf("HybridKem.Decapsulate", System.StringComparison.Ordinal);
        var verifyIndex = fixedCode.IndexOf("HybridSignature.Verify", System.StringComparison.Ordinal);
        Assert.True(verifyIndex > -1 && decapIndex > -1, "Both calls should still be present.");
        Assert.True(verifyIndex < decapIndex,
            $"Verify must precede Decapsulate after fix. verify={verifyIndex} decap={decapIndex}\n---\n{fixedCode}");
    }
}
