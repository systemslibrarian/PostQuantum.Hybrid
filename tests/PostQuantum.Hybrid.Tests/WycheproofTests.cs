using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Xunit;

namespace PostQuantum.Hybrid.Tests;

/// <summary>
/// Runs the Wycheproof (C2SP) negative test vectors against the classical
/// primitives this library delegates to (X25519, Ed25519 via BouncyCastle)
/// and against the library's own hybrid paths, plus the Wycheproof
/// ML-DSA-65 verify vectors. The vectors are vendored under
/// <c>fixtures/wycheproof/</c> (fetched by <c>tools/fetch-wycheproof.ps1</c>;
/// see the NOTICE.md there for provenance and license). Like
/// <see cref="NistAcvpKatTests"/>, a missing fixture is a hard failure,
/// not a skip.
/// </summary>
public class WycheproofTests
{
    // Wire-format constants pinned by docs/SPEC.md (tests deliberately use
    // literals rather than the library's internal constants — same pattern
    // as AlgorithmSizesTests).
    private const int X25519PublicKeyBytes = 32;
    private const int Ed25519SignatureBytes = 64;
    private const int MlKem768PublicKeyBytes = 1184;
    private const int MlDsa65SignatureBytes = 3309;

    private static string FixturePath(string name) =>
        Path.Combine(AppContext.BaseDirectory, "fixtures", "wycheproof", name);

    private static JsonDocument Load(string name)
    {
        var path = FixturePath(name);
        Assert.True(File.Exists(path),
            $"Vendored Wycheproof fixture missing: {path}. Run tools/fetch-wycheproof.ps1 and commit the output.");
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

    /// <summary>
    /// The per-group public key: newer Wycheproof files nest it as
    /// <c>publicKey.pk</c>, older ones as <c>key.pk</c>, some as a flat
    /// <c>publicKey</c> hex string.
    /// </summary>
    private static byte[]? GroupPublicKey(JsonElement group)
    {
        if (group.TryGetProperty("publicKey", out var pkObj))
        {
            if (pkObj.ValueKind == JsonValueKind.Object)
            {
                return TryHex(pkObj, "pk");
            }
            if (pkObj.ValueKind == JsonValueKind.String)
            {
                try { return Convert.FromHexString(pkObj.GetString()!); }
                catch (FormatException) { return null; }
            }
        }
        if (group.TryGetProperty("key", out var keyObj) &&
            keyObj.ValueKind == JsonValueKind.Object)
        {
            return TryHex(keyObj, "pk");
        }
        return null;
    }

    private static string Result(JsonElement test) =>
        test.GetProperty("result").GetString()!;

    private static bool HasFlag(JsonElement test, string flag) =>
        test.TryGetProperty("flags", out var flags) &&
        flags.ValueKind == JsonValueKind.Array &&
        flags.EnumerateArray().Any(f => f.GetString() == flag);

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
    // X25519: the agreement primitive we delegate to must compute the
    // published shared secrets and must fail closed (throw) on inputs
    // that would produce the all-zero secret (low-order public keys).
    // ---------------------------------------------------------------

    [Fact]
    public void X25519_Agreement_MatchesWycheproof_AndRejectsZeroSecrets()
    {
        using var doc = Load("x25519_test.json");
        int matched = 0, zeroRejected = 0;

        foreach (var (group, test) in Vectors(doc))
        {
            var priv = TryHex(test, "private");
            var pub = TryHex(test, "public");
            var shared = TryHex(test, "shared");
            if (priv is null || pub is null || shared is null ||
                priv.Length != 32 || pub.Length != 32)
            {
                continue;
            }
            var tcId = test.GetProperty("tcId").GetInt32();
            var expectZero = shared.All(b => b == 0);

            byte[]? actual = null;
            try
            {
                var agreement = new X25519Agreement();
                agreement.Init(new X25519PrivateKeyParameters(priv));
                actual = new byte[agreement.AgreementSize];
                agreement.CalculateAgreement(new X25519PublicKeyParameters(pub), actual, 0);
            }
            catch (InvalidOperationException)
            {
                actual = null;
            }
            catch (CryptoException)
            {
                actual = null;
            }

            if (expectZero)
            {
                // Low-order public key. BouncyCastle's X25519Agreement must
                // refuse to hand back the all-zero secret — this is the
                // fail-closed behavior the library inherits.
                Assert.True(actual is null,
                    $"tcId {tcId}: expected BC to reject the all-zero X25519 shared secret, but it returned one.");
                zeroRejected++;
            }
            else if (Result(test) is "valid" or "acceptable")
            {
                Assert.True(actual is not null,
                    $"tcId {tcId}: BC rejected an agreement Wycheproof marks {Result(test)}.");
                Assert.True(shared.AsSpan().SequenceEqual(actual),
                    $"tcId {tcId}: X25519 shared secret mismatch.");
                matched++;
            }
            // result == "invalid" with a nonzero published secret has no
            // single correct behavior for a raw-key API; not asserted.
        }

        Assert.True(matched > 0, "No valid X25519 Wycheproof vectors were exercised.");
        Assert.True(zeroRejected > 0, "No low-order/zero-secret X25519 Wycheproof vectors were exercised.");
    }

    [Fact]
    public void X25519_LowOrderRecipientKey_EncapsulateFailsClosed()
    {
        using var doc = Load("x25519_test.json");

        // A structurally valid hybrid public key whose X25519 component we
        // replace with each low-order point from the vectors.
        using var pair = HybridKem.GenerateKeyPair();
        var template = pair.PublicKey.Export();
        Assert.Equal(1 + X25519PublicKeyBytes + MlKem768PublicKeyBytes, template.Length);

        var lowOrderPoints = Vectors(doc)
            .Select(v => (Pub: TryHex(v.Test, "public"), Shared: TryHex(v.Test, "shared")))
            .Where(v => v.Pub is { Length: 32 } && v.Shared is not null && v.Shared.All(b => b == 0))
            .Select(v => v.Pub!)
            .DistinctBy(Convert.ToHexString)
            .ToList();
        Assert.True(lowOrderPoints.Count > 0,
            "No low-order X25519 public keys found in the Wycheproof vectors.");

        foreach (var point in lowOrderPoints)
        {
            var blob = (byte[])template.Clone();
            point.CopyTo(blob, 1);
            var publicKey = HybridKemPublicKey.Import(blob);

            // Fail-closed: encapsulating against a low-order X25519
            // component must throw, never return a shared secret whose
            // classical contribution is the all-zero string.
            var threw = false;
            try
            {
                using var result = HybridKem.Encapsulate(publicKey);
            }
            catch (Exception)
            {
                threw = true;
            }
            Assert.True(threw,
                $"Encapsulate returned a secret for low-order X25519 point {Convert.ToHexString(point)}.");
        }
    }

    // ---------------------------------------------------------------
    // Ed25519: Wycheproof's signature negatives (malleability,
    // non-canonical S, truncated/extended sigs, ...) driven through the
    // library's own HybridSignature.Verify by grafting each vector onto
    // a hybrid blob with a freshly generated, always-valid ML-DSA half —
    // so the verdict isolates the Ed25519 component.
    // ---------------------------------------------------------------

    [Fact]
    public void Ed25519_Verify_MatchesWycheproof_ThroughHybridVerify()
    {
        using var doc = Load("ed25519_test.json");

        var gen = new MLDsaKeyPairGenerator();
        gen.Init(new MLDsaKeyGenerationParameters(new SecureRandom(), MLDsaParameters.ml_dsa_65));
        var mldsaPair = gen.GenerateKeyPair();
        var mldsaPub = ((MLDsaPublicKeyParameters)mldsaPair.Public).GetEncoded();
        var signer = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: false);
        signer.Init(forSigning: true, (MLDsaPrivateKeyParameters)mldsaPair.Private);

        int validCount = 0, invalidCount = 0;

        foreach (var (group, test) in Vectors(doc))
        {
            var edPk = GroupPublicKey(group);
            if (edPk is not { Length: 32 })
            {
                continue;
            }
            var msg = TryHex(test, "msg");
            var wpSig = TryHex(test, "sig");
            if (msg is null || wpSig is null)
            {
                continue;
            }
            var tcId = test.GetProperty("tcId").GetInt32();
            var result = Result(test);

            var pkBlob = new byte[1 + edPk.Length + mldsaPub.Length];
            pkBlob[0] = (byte)HybridSignatureAlgorithm.Ed25519MlDsa65;
            edPk.CopyTo(pkBlob, 1);
            mldsaPub.CopyTo(pkBlob, 1 + edPk.Length);
            var publicKey = HybridSignaturePublicKey.Import(pkBlob);

            signer.BlockUpdate(msg);
            var mldsaSig = signer.GenerateSignature();
            Assert.Equal(MlDsa65SignatureBytes, mldsaSig.Length);

            var sigBlob = new byte[1 + wpSig.Length + mldsaSig.Length];
            sigBlob[0] = (byte)HybridSignatureAlgorithm.Ed25519MlDsa65;
            wpSig.CopyTo(sigBlob, 1);
            mldsaSig.CopyTo(sigBlob, 1 + wpSig.Length);

            var verified = HybridSignature.Verify(publicKey, msg, sigBlob);

            switch (result)
            {
                case "valid":
                    Assert.True(verified, $"tcId {tcId}: valid Ed25519 vector rejected through hybrid Verify.");
                    validCount++;
                    break;
                case "invalid":
                    Assert.False(verified, $"tcId {tcId}: invalid Ed25519 vector ({test.GetProperty("comment")}) accepted through hybrid Verify.");
                    invalidCount++;
                    break;
                // "acceptable" (if present) is implementation-defined; not asserted.
            }
        }

        Assert.True(validCount > 0, "No valid Ed25519 Wycheproof vectors were exercised.");
        Assert.True(invalidCount > 0, "No invalid Ed25519 Wycheproof vectors were exercised.");
    }

    // ---------------------------------------------------------------
    // ML-DSA-65 verify: Wycheproof's negative classes on top of the
    // ACVP sigVer vectors already covered by NistAcvpKatTests.
    // ---------------------------------------------------------------

    [Fact]
    public void MlDsa65_Verify_MatchesWycheproof()
    {
        // The upstream file name has varied across Wycheproof revisions;
        // tools/fetch-wycheproof.ps1 discovers it by this same pattern.
        var dir = Path.Combine(AppContext.BaseDirectory, "fixtures", "wycheproof");
        var matches = Directory.Exists(dir)
            ? Directory.GetFiles(dir, "mldsa_65*verify*.json")
            : Array.Empty<string>();
        Assert.True(matches.Length > 0,
            $"No ML-DSA-65 verify Wycheproof fixture under {dir}. Run tools/fetch-wycheproof.ps1 and commit the output.");

        int validCount = 0, invalidCount = 0;

        foreach (var file in matches.Order())
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(file));
            foreach (var (group, test) in Vectors(doc))
            {
                var pk = GroupPublicKey(group);
                var msg = TryHex(test, "msg");
                var sig = TryHex(test, "sig");
                if (pk is null || msg is null || sig is null)
                {
                    continue;
                }
                // The library signs/verifies pure ML-DSA with an empty
                // context; vectors with a non-empty ctx exercise a mode we
                // do not ship.
                var ctx = TryHex(test, "ctx");
                if (ctx is { Length: > 0 })
                {
                    continue;
                }
                var tcId = test.GetProperty("tcId").GetInt32();
                var result = Result(test);

                var verified = VerifyMlDsaTolerantOfMalformed(pk, msg, sig);

#if NET10_0_OR_GREATER
                if (System.Security.Cryptography.MLDsa.IsSupported)
                {
                    var native = VerifyMlDsaNativeTolerantOfMalformed(pk, msg, sig);
                    Assert.True(verified == native,
                        $"tcId {tcId}: BC ({verified}) and native ({native}) ML-DSA verify disagree.");
                }
#endif

                switch (result)
                {
                    case "valid":
                        Assert.True(verified, $"tcId {tcId}: valid ML-DSA-65 vector rejected.");
                        validCount++;
                        break;
                    case "invalid":
                        Assert.False(verified, $"tcId {tcId}: invalid ML-DSA-65 vector ({test.GetProperty("comment")}) accepted.");
                        invalidCount++;
                        break;
                }
            }
        }

        Assert.True(validCount > 0, "No valid ML-DSA-65 Wycheproof vectors were exercised.");
        Assert.True(invalidCount > 0, "No invalid ML-DSA-65 Wycheproof vectors were exercised.");
    }

    private static bool VerifyMlDsaTolerantOfMalformed(byte[] pk, byte[] msg, byte[] sig)
    {
        try
        {
            var pub = MLDsaPublicKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_65, pk);
            var verifier = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: false);
            verifier.Init(forSigning: false, pub);
            verifier.BlockUpdate(msg);
            return verifier.VerifySignature(sig);
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
    private static bool VerifyMlDsaNativeTolerantOfMalformed(byte[] pk, byte[] msg, byte[] sig)
    {
        try
        {
            using var dsa = System.Security.Cryptography.MLDsa.ImportMLDsaPublicKey(
                System.Security.Cryptography.MLDsaAlgorithm.MLDsa65, pk);
            return dsa.VerifyData(msg, sig, context: default);
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }
#endif
}
