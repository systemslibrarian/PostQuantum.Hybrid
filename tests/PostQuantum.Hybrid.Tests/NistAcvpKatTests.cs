using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Xunit;

namespace PostQuantum.Hybrid.Tests;

/// <summary>
/// Validates the BouncyCastle backend (and, on .NET 10 where the OS
/// supports it, the native backend) against the **published NIST ACVP
/// gen-val vectors** for the final FIPS 203 / FIPS 204 standards. The
/// vectors are vendored under <c>fixtures/nist-acvp/</c> (filtered to
/// ML-KEM-768 / ML-DSA-65 by <c>tools/fetch-nist-acvp.ps1</c>; see the
/// NOTICE.md there for provenance), so unlike <see cref="NistKatRunner"/>
/// these tests run unconditionally — a missing fixture is a hard failure,
/// not a skip.
/// </summary>
public class NistAcvpKatTests
{
    // Wire-format constants pinned by docs/SPEC.md (tests deliberately use
    // literals rather than the library's internal constants — same pattern
    // as AlgorithmSizesTests).
    private const int MlKem768CiphertextBytes = 1088;
    private const int MlKem768SharedSecretBytes = 32;

    private static string FixturePath(string name) =>
        Path.Combine(AppContext.BaseDirectory, "fixtures", "nist-acvp", name);

    private static JsonDocument Load(string name)
    {
        var path = FixturePath(name);
        Assert.True(File.Exists(path),
            $"Vendored ACVP fixture missing: {path}. Run tools/fetch-nist-acvp.ps1 and commit the output.");
        // ReadAllText (not ReadAllBytes): it strips a UTF-8 BOM, which
        // Windows PowerShell 5.1 writes and JsonDocument.Parse rejects.
        return JsonDocument.Parse(File.ReadAllText(path));
    }

    private static byte[]? TryHex(JsonElement element, string property)
    {
        if (element.ValueKind == JsonValueKind.Object &&
            element.TryGetProperty(property, out var value) &&
            value.ValueKind == JsonValueKind.String)
        {
            try
            {
                return Convert.FromHexString(value.GetString()!);
            }
            catch (FormatException)
            {
                return null;
            }
        }
        return null;
    }

    /// <summary>Test-level value, falling back to the group level.</summary>
    private static byte[]? TryHex(JsonElement test, JsonElement group, string property) =>
        TryHex(test, property) ?? TryHex(group, property);

    private static IEnumerable<(JsonElement Group, JsonElement Test)> Vectors(JsonDocument doc)
    {
        foreach (var group in doc.RootElement.GetProperty("testGroups").EnumerateArray())
        {
            foreach (var test in group.GetProperty("tests").EnumerateArray())
            {
                yield return (group, test);
            }
        }
    }

    // ---------------------------------------------------------------
    // ML-KEM-768 keyGen: (d, z) -> ek (and dk where directly comparable)
    // ---------------------------------------------------------------

    public static IEnumerable<(byte[] Seed, byte[] Ek, byte[] Dk)> MlKemKeyGenVectors()
    {
        using var doc = Load("ML-KEM-768-keyGen.json");
        foreach (var (group, test) in Vectors(doc))
        {
            var d = TryHex(test, group, "d");
            var z = TryHex(test, group, "z");
            var ek = TryHex(test, group, "ek");
            var dk = TryHex(test, group, "dk");
            if (d is null || z is null || ek is null || dk is null)
            {
                continue;
            }
            // FIPS 203 seed convention: d || z (d first).
            var seed = new byte[d.Length + z.Length];
            d.CopyTo(seed.AsSpan());
            z.CopyTo(seed.AsSpan(d.Length));
            yield return (seed, ek, dk);
        }
    }

    [Fact]
    public void MlKem768_KeyGen_MatchesBouncyCastle()
    {
        var count = 0;
        foreach (var (seed, ek, dk) in MlKemKeyGenVectors())
        {
            var priv = MLKemPrivateKeyParameters.FromSeed(MLKemParameters.ml_kem_768, seed);
            Assert.Equal(ek, priv.GetPublicKey().GetEncoded());

            // Functional dk check: the published expanded dk and our
            // seed-derived key must decapsulate a fresh ciphertext to the
            // same shared secret.
            var pub = MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, ek);
            var ct = new byte[MlKem768CiphertextBytes];
            var ssEnc = new byte[MlKem768SharedSecretBytes];
            var enc = new MLKemEncapsulator(MLKemParameters.ml_kem_768);
            enc.Init(pub);
            enc.Encapsulate(ct, ssEnc);

            var ssFromSeedKey = Decapsulate(priv, ct);
            var ssFromPublishedDk = Decapsulate(
                MLKemPrivateKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, dk), ct);
            Assert.Equal(ssEnc, ssFromSeedKey);
            Assert.Equal(ssEnc, ssFromPublishedDk);
            count++;
        }
        Assert.True(count > 0, "No usable ML-KEM-768 keyGen vectors found in the vendored ACVP fixture.");
    }

    // ---------------------------------------------------------------
    // ML-KEM-768 encapDecap (decapsulation): dk + c -> k
    // Includes implicit-rejection vectors: k is the published FIPS 203
    // result either way, so plain equality covers them.
    // ---------------------------------------------------------------

    public static IEnumerable<(byte[] Dk, byte[] C, byte[] K)> MlKemDecapVectors()
    {
        using var doc = Load("ML-KEM-768-encapDecap.json");
        foreach (var (group, test) in Vectors(doc))
        {
            var dk = TryHex(test, group, "dk");
            var c = TryHex(test, group, "c");
            var k = TryHex(test, group, "k");
            // Encapsulation groups have no dk; ciphertext-check groups have
            // no k. Skip anything that is not a plain decapsulation vector,
            // and anything whose ciphertext is not the ML-KEM-768 length
            // (deliberately wrong-length inputs are exercised by our own
            // fail-closed tests at the hybrid layer).
            if (dk is null || c is null || k is null ||
                c.Length != MlKem768CiphertextBytes)
            {
                continue;
            }
            yield return (dk, c, k);
        }
    }

    [Fact]
    public void MlKem768_Decapsulation_MatchesBouncyCastle()
    {
        var count = 0;
        foreach (var (dk, c, k) in MlKemDecapVectors())
        {
            var priv = MLKemPrivateKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, dk);
            Assert.Equal(k, Decapsulate(priv, c));
            count++;
        }
        Assert.True(count > 0, "No usable ML-KEM-768 decapsulation vectors found in the vendored ACVP fixture.");
    }

    private static byte[] Decapsulate(MLKemPrivateKeyParameters priv, byte[] ciphertext)
    {
        var ss = new byte[MlKem768SharedSecretBytes];
        var dec = new MLKemDecapsulator(MLKemParameters.ml_kem_768);
        dec.Init(priv);
        dec.Decapsulate(ciphertext, ss);
        return ss;
    }

    // ---------------------------------------------------------------
    // ML-DSA-65 keyGen: seed -> pk
    // ---------------------------------------------------------------

    public static IEnumerable<(byte[] Seed, byte[] Pk)> MlDsaKeyGenVectors()
    {
        using var doc = Load("ML-DSA-65-keyGen.json");
        foreach (var (group, test) in Vectors(doc))
        {
            var seed = TryHex(test, group, "seed");
            var pk = TryHex(test, group, "pk");
            if (seed is null || pk is null || seed.Length != 32)
            {
                continue;
            }
            yield return (seed, pk);
        }
    }

    [Fact]
    public void MlDsa65_KeyGen_MatchesBouncyCastle()
    {
        var count = 0;
        foreach (var (seed, pk) in MlDsaKeyGenVectors())
        {
            var priv = MLDsaPrivateKeyParameters.FromSeed(MLDsaParameters.ml_dsa_65, seed);
            Assert.Equal(pk, priv.GetPublicKey().GetEncoded());
            count++;
        }
        Assert.True(count > 0, "No usable ML-DSA-65 keyGen vectors found in the vendored ACVP fixture.");
    }

    // ---------------------------------------------------------------
    // ML-DSA-65 sigVer: pk + message + signature -> testPassed.
    // This is the negative-vector set: NIST deliberately includes
    // modified signatures/messages with testPassed = false.
    // ---------------------------------------------------------------

    public static IEnumerable<(byte[] Pk, byte[] Message, byte[] Signature, byte[] Context, bool Expected)> MlDsaSigVerVectors()
    {
        using var doc = Load("ML-DSA-65-sigVer.json");
        foreach (var (group, test) in Vectors(doc))
        {
            // Our backends implement "pure" external-interface ML-DSA, so
            // skip pre-hashed and internal-interface groups. Per-test FIPS 204
            // context strings (most ACVP tests carry a random one — including
            // every negative vector) are passed through to the verifier.
            if (group.TryGetProperty("signatureInterface", out var iface) &&
                iface.GetString() != "external")
            {
                continue;
            }
            if (group.TryGetProperty("preHash", out var preHash) &&
                preHash.GetString() is not (null or "pure" or "none"))
            {
                continue;
            }
            var context = TryHex(test, group, "context") ?? [];
            if (context.Length > 255)
            {
                continue; // FIPS 204 caps ctx at 255 bytes; longer is API misuse, not "invalid signature"
            }

            var pk = TryHex(test, group, "pk");
            var message = TryHex(test, group, "message");
            var signature = TryHex(test, group, "signature");
            if (pk is null || message is null || signature is null ||
                !test.TryGetProperty("testPassed", out var passed) ||
                passed.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            {
                continue;
            }
            yield return (pk, message, signature, context, passed.GetBoolean());
        }
    }

    [Fact]
    public void MlDsa65_SigVer_MatchesBouncyCastle()
    {
        var count = 0;
        var negatives = 0;
        foreach (var (pk, message, signature, context, expected) in MlDsaSigVerVectors())
        {
            var pub = MLDsaPublicKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_65, pk);
            var verifier = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: false);
            ICipherParameters initParams = context.Length > 0
                ? new ParametersWithContext(pub, context)
                : pub;
            verifier.Init(forSigning: false, initParams);
            verifier.BlockUpdate(message);
            var actual = VerifyTolerantOfMalformed(verifier, signature);
            Assert.True(expected == actual,
                $"sigVer mismatch: expected testPassed={expected}, BouncyCastle returned {actual}.");
            count++;
            if (!expected)
            {
                negatives++;
            }
        }
        Assert.True(count > 0, "No usable ML-DSA-65 sigVer vectors found in the vendored ACVP fixture.");
        Assert.True(negatives > 0, "The vendored sigVer fixture contained no negative vectors — the set has lost its teeth.");
    }

    /// <summary>
    /// A structurally malformed signature must mean "invalid", never an
    /// unhandled exception — mirror the fail-closed contract the library
    /// itself provides at the hybrid layer.
    /// </summary>
    private static bool VerifyTolerantOfMalformed(MLDsaSigner verifier, byte[] signature)
    {
        try
        {
            return verifier.VerifySignature(signature);
        }
        catch (CryptoException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

#if NET10_0_OR_GREATER
    // ---------------------------------------------------------------
    // Native .NET 10 backend, when the OS exposes ML-KEM / ML-DSA.
    // ---------------------------------------------------------------

    [Fact]
    public void MlKem768_KeyGen_MatchesNative_WhenSupported()
    {
        if (!System.Security.Cryptography.MLKem.IsSupported)
        {
            return; // platform does not expose ML-KEM; BC test above still ran
        }
        var count = 0;
        foreach (var (seed, ek, dk) in MlKemKeyGenVectors())
        {
            using var kem = System.Security.Cryptography.MLKem.ImportPrivateSeed(
                System.Security.Cryptography.MLKemAlgorithm.MLKem768, seed);
            Assert.Equal(ek, kem.ExportEncapsulationKey());
            Assert.Equal(dk, kem.ExportDecapsulationKey());
            count++;
        }
        Assert.True(count > 0);
    }

    [Fact]
    public void MlKem768_Decapsulation_MatchesNative_WhenSupported()
    {
        if (!System.Security.Cryptography.MLKem.IsSupported)
        {
            return;
        }
        var count = 0;
        foreach (var (dk, c, k) in MlKemDecapVectors())
        {
            using var kem = System.Security.Cryptography.MLKem.ImportDecapsulationKey(
                System.Security.Cryptography.MLKemAlgorithm.MLKem768, dk);
            var ss = new byte[MlKem768SharedSecretBytes];
            kem.Decapsulate(c, ss);
            Assert.Equal(k, ss);
            count++;
        }
        Assert.True(count > 0);
    }

    [Fact]
    public void MlDsa65_KeyGen_MatchesNative_WhenSupported()
    {
        if (!System.Security.Cryptography.MLDsa.IsSupported)
        {
            return;
        }
        var count = 0;
        foreach (var (seed, pk) in MlDsaKeyGenVectors())
        {
            using var dsa = System.Security.Cryptography.MLDsa.ImportMLDsaPrivateSeed(
                System.Security.Cryptography.MLDsaAlgorithm.MLDsa65, seed);
            Assert.Equal(pk, dsa.ExportMLDsaPublicKey());
            count++;
        }
        Assert.True(count > 0);
    }

    [Fact]
    public void MlDsa65_SigVer_MatchesNative_WhenSupported()
    {
        if (!System.Security.Cryptography.MLDsa.IsSupported)
        {
            return;
        }
        var count = 0;
        foreach (var (pk, message, signature, context, expected) in MlDsaSigVerVectors())
        {
            using var dsa = System.Security.Cryptography.MLDsa.ImportMLDsaPublicKey(
                System.Security.Cryptography.MLDsaAlgorithm.MLDsa65, pk);
            bool actual;
            try
            {
                actual = dsa.VerifyData(message, signature, context);
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                actual = false;
            }
            Assert.True(expected == actual,
                $"native sigVer mismatch: expected testPassed={expected}, got {actual}.");
            count++;
        }
        Assert.True(count > 0);
    }
#endif
}
