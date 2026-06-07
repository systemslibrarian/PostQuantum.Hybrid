using System.Security.Cryptography;
using Xunit;

namespace PostQuantum.Hybrid.Fuzz;

/// <summary>
/// Targeted property-style fuzzing for the library's parsers. Each test
/// drives N randomly-generated or mutated inputs through an import/parse
/// API and asserts the *only* possible failure modes are clean exceptions
/// (CryptographicException, FormatException, ArgumentNullException).
/// Any other exception type indicates an unhandled parser bug.
///
/// Seeds are deterministic so failures are reproducible.
/// </summary>
public class ParserFuzzTests
{
    private const int Iterations = 1000;

    private static readonly Type[] ExpectedExceptionTypes =
    [
        typeof(CryptographicException),
        typeof(FormatException),
        typeof(ArgumentNullException),
        typeof(ArgumentOutOfRangeException),
    ];

    private static void AssertOnlyExpectedExceptions(Action action)
    {
        try
        {
            action();
        }
        catch (Exception ex)
        {
            Assert.Contains(ex.GetType(), ExpectedExceptionTypes);
        }
    }

    [Fact]
    public void FuzzKemPublicKey_RandomBytesNeverCrash()
    {
        var rng = new Random(0xC0FFEE);
        for (var i = 0; i < Iterations; i++)
        {
            var len = rng.Next(0, 2500);
            var bytes = new byte[len];
            rng.NextBytes(bytes);
            AssertOnlyExpectedExceptions(() => HybridKemPublicKey.Import(bytes));
        }
    }

    [Fact]
    public void FuzzKemPrivateKey_RandomBytesNeverCrash()
    {
        var rng = new Random(0xBADC0DE);
        for (var i = 0; i < Iterations; i++)
        {
            var len = rng.Next(0, 5000);
            var bytes = new byte[len];
            rng.NextBytes(bytes);
            AssertOnlyExpectedExceptions(() =>
            {
                using var _ = HybridKemPrivateKey.Import(bytes);
            });
        }
    }

    [Fact]
    public void FuzzKemCiphertext_RandomBytesNeverCrash()
    {
        var rng = new Random(unchecked((int)0xFEEDBEEF));
        for (var i = 0; i < Iterations; i++)
        {
            var len = rng.Next(0, 2200);
            var bytes = new byte[len];
            rng.NextBytes(bytes);
            AssertOnlyExpectedExceptions(() => HybridKemCiphertext.FromBytes(bytes));
        }
    }

    [Fact]
    public void FuzzSigPublicKey_RandomBytesNeverCrash()
    {
        var rng = new Random(0xABCDEF);
        for (var i = 0; i < Iterations; i++)
        {
            var len = rng.Next(0, 4000);
            var bytes = new byte[len];
            rng.NextBytes(bytes);
            AssertOnlyExpectedExceptions(() => HybridSignaturePublicKey.Import(bytes));
        }
    }

    [Fact]
    public void FuzzSigPrivateKey_RandomBytesNeverCrash()
    {
        var rng = new Random(0x123456);
        for (var i = 0; i < Iterations; i++)
        {
            var len = rng.Next(0, 8500);
            var bytes = new byte[len];
            rng.NextBytes(bytes);
            AssertOnlyExpectedExceptions(() =>
            {
                using var _ = HybridSignaturePrivateKey.Import(bytes);
            });
        }
    }

    [Fact]
    public void FuzzVerify_RandomSignaturesAgainstRealKey_NeverCrash()
    {
        // Verify must return false (never throw) for arbitrary signature blobs.
        using var pair = HybridSignature.GenerateKeyPair();
        var msg = "fuzz me"u8.ToArray();
        var rng = new Random(0x999);

        for (var i = 0; i < Iterations; i++)
        {
            var len = rng.Next(0, 4000);
            var sig = new byte[len];
            rng.NextBytes(sig);
            try
            {
                var result = HybridSignature.Verify(pair.PublicKey, msg, sig);
                // No throw is enough; result is "false" overwhelmingly. We only
                // assert no exception. A successful verify on random bytes
                // would be a catastrophic finding.
                _ = result;
            }
            catch (Exception ex)
            {
                Assert.Fail($"Verify threw {ex.GetType().Name}: {ex.Message}");
            }
        }
    }

    [Fact]
    public void FuzzBitFlipKemPublicKey_NeverCrash()
    {
        using var pair = HybridKem.GenerateKeyPair();
        var original = pair.PublicKey.Export();
        var rng = new Random(0x42);

        for (var i = 0; i < Iterations; i++)
        {
            var mutated = (byte[])original.Clone();
            // Flip 1-5 random bits.
            var flips = rng.Next(1, 6);
            for (var f = 0; f < flips; f++)
            {
                var byteIdx = rng.Next(mutated.Length);
                var bitIdx = rng.Next(8);
                mutated[byteIdx] ^= (byte)(1 << bitIdx);
            }
            // Import either succeeds (parses to a different valid key) or
            // throws cleanly; never crashes.
            AssertOnlyExpectedExceptions(() => HybridKemPublicKey.Import(mutated));
        }
    }

    [Fact]
    public void FuzzBitFlipSignature_NeverCrash()
    {
        using var pair = HybridSignature.GenerateKeyPair();
        var msg = "bitflip target"u8.ToArray();
        var goodSig = HybridSignature.Sign(pair.PrivateKey, msg);
        var rng = new Random(0x7F);

        for (var i = 0; i < Iterations; i++)
        {
            var mutated = (byte[])goodSig.Clone();
            var flips = rng.Next(1, 6);
            for (var f = 0; f < flips; f++)
            {
                var byteIdx = rng.Next(mutated.Length);
                var bitIdx = rng.Next(8);
                mutated[byteIdx] ^= (byte)(1 << bitIdx);
            }
            // Should return false (or true with vanishingly small probability
            // if no meaningful change), never throw.
            try
            {
                _ = HybridSignature.Verify(pair.PublicKey, msg, mutated);
            }
            catch (Exception ex)
            {
                Assert.Fail($"Verify threw {ex.GetType().Name}: {ex.Message}");
            }
        }
    }

    [Fact]
    public void FuzzPemImport_RandomGarbage_OnlyExpectedExceptions()
    {
        var rng = new Random(0xBEEF);
        for (var i = 0; i < 200; i++) // PEM parse is slow, fewer iterations
        {
            var len = rng.Next(0, 5000);
            var sb = new System.Text.StringBuilder(len);
            for (var c = 0; c < len; c++)
            {
                // Bias toward printable ASCII so we exercise the base64/marker
                // detection rather than just bombing on bytes outside ASCII.
                sb.Append((char)(rng.Next(0x20, 0x7F)));
            }
            var s = sb.ToString();
            AssertOnlyExpectedExceptions(() => HybridKemPublicKey.ImportPem(s));
        }
    }
}
