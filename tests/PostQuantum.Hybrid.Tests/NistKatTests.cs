using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Xunit;
#if NET10_0_OR_GREATER
using SystemMlKem = System.Security.Cryptography.MLKem;
using SystemMlDsa = System.Security.Cryptography.MLDsa;
using SystemMlKemAlg = System.Security.Cryptography.MLKemAlgorithm;
using SystemMlDsaAlg = System.Security.Cryptography.MLDsaAlgorithm;
#endif

namespace PostQuantum.Hybrid.Tests;

/// <summary>
/// FIPS-203 / FIPS-204 regression vectors. Each vector pins the
/// SHA-256 of the public AND private key derived deterministically
/// from a fixed seed. On <c>net10.0</c>, every vector is additionally
/// cross-checked against the native <c>System.Security.Cryptography.MLKem</c>
/// / <c>MLDsa</c> implementation when the underlying OS exposes it.
/// </summary>
/// <remarks>
/// <para><b>Provenance:</b> these vectors are derived from
/// BouncyCastle's deterministic <c>FromSeed</c> for the chosen seeds.
/// They are NOT the published NIST .rsp KAT vectors — those are
/// fetched at workflow time when <c>vars.NIST_KAT_MIRROR</c> is set
/// (see <c>.github/workflows/nist-kats.yml</c>). The purpose here is
/// to catch (a) drift in BouncyCastle's implementation across version
/// bumps and (b) divergence between BC and the native .NET 10 backend
/// for the same seed.</para>
/// <para>If a hash assertion fires after a routine BC bump, do not
/// blindly update the pinned hash — investigate the BC release notes
/// for behavior changes first.</para>
/// </remarks>
public class NistKatTests
{
    public static IEnumerable<object[]> MlKemSeeds() => new[]
    {
        new object[]
        {
            // Vector 0: low-byte ramp (d || z = 0x00..0x3f)
            Convert.FromHexString(
                "0001020304050607" + "08090a0b0c0d0e0f" +
                "1011121314151617" + "18191a1b1c1d1e1f" +
                "2021222324252627" + "28292a2b2c2d2e2f" +
                "3031323334353637" + "38393a3b3c3d3e3f"),
            "0b7934c83125c788995e2ba6bd761e33046b3e40571be53e023309a29f398cc9",
            "0c2ae860c2b0989975355462da320c8c0f08ce379fc25db9dcf4e5a1a5158115",
        },
        new object[]
        {
            // Vector 1: alternating nibbles 0xa5/0x5a
            Convert.FromHexString(
                "a5a5a5a5a5a5a5a5" + "5a5a5a5a5a5a5a5a" +
                "a5a5a5a5a5a5a5a5" + "5a5a5a5a5a5a5a5a" +
                "a5a5a5a5a5a5a5a5" + "5a5a5a5a5a5a5a5a" +
                "a5a5a5a5a5a5a5a5" + "5a5a5a5a5a5a5a5a"),
            "e23aa5667835064641886f7e519e656371edcbe231559a93d9c43c2e0b043fcf",
            "466d398128c5904fe4c013a62473cd651dee7675553361ef16ac47e867832312",
        },
        new object[]
        {
            // Vector 2: all 0xff (boundary)
            Convert.FromHexString(
                "ffffffffffffffff" + "ffffffffffffffff" +
                "ffffffffffffffff" + "ffffffffffffffff" +
                "ffffffffffffffff" + "ffffffffffffffff" +
                "ffffffffffffffff" + "ffffffffffffffff"),
            "b212c1e61145cc7f4fb3ff1e6adf823f66a69e0fca3cd7d571ab259a96348509",
            "e62f8736139c2f15fef4d7da65f5f3b3d8ff56d2e0f528bcef68df1c2b16fcc8",
        },
    };

    public static IEnumerable<object[]> MlDsaSeeds() => new[]
    {
        new object[]
        {
            Convert.FromHexString("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"),
            "ddf723ba0cc75408d1a3a8dc48f8302bfc25bd2cacf9374c28d861deea3a7184",
            "8a5d0cd4d3769a8d918879faa79ca01636f25f92224e8a1a4d7bcc43e2f0166c",
        },
        new object[]
        {
            Convert.FromHexString("a5a5a5a5a5a5a5a55a5a5a5a5a5a5a5aa5a5a5a5a5a5a5a55a5a5a5a5a5a5a5a"),
            "3cd9352b3fe5ce0a02fc417638808d4391c1fe86d45ce818ff828c1df4234f62",
            "eb55c88c55ca723057a331a8cbc8bbefb9b894f2d7773e609938f9bdcb1af41b",
        },
        new object[]
        {
            Convert.FromHexString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            "accc50ec0bce614855e62e04741f54367add7a6ec074db7369f7484e6067e224",
            "11681dc1c20ee8ab3198e19858b1498c25f49c301d9c2f2256b8db4c1ef0dcae",
        },
    };

    [Theory]
    [MemberData(nameof(MlKemSeeds))]
    public void MlKem_FromSeed_PublicAndPrivateKeyHashes_AreStable(byte[] seed, string expectedPubHash, string expectedPrivHash)
    {
        var priv = MLKemPrivateKeyParameters.FromSeed(MLKemParameters.ml_kem_768, seed);
        var pubBytes = priv.GetPublicKey().GetEncoded();
        var privBytes = priv
            .WithPreferredFormat(MLKemPrivateKeyParameters.Format.SeedAndEncoding)
            .GetEncoded();

        Assert.Equal(1184, pubBytes.Length);
        var actualPubHash = Convert.ToHexString(SHA256.HashData(pubBytes)).ToLowerInvariant();
        var actualPrivHash = Convert.ToHexString(SHA256.HashData(privBytes)).ToLowerInvariant();

        if (expectedPubHash.StartsWith("PLACEHOLDER") || expectedPrivHash.StartsWith("PLACEHOLDER"))
        {
            // Help future-me: when a placeholder is in place, print the
            // discovered hash so it can be pinned. Test still passes.
            Console.Error.WriteLine($"MlKem seed[0]={seed[0]:x2} pubHash={actualPubHash} privHash={actualPrivHash}");
            return;
        }

        Assert.Equal(expectedPubHash, actualPubHash);
        Assert.Equal(expectedPrivHash, actualPrivHash);
    }

    [Theory]
    [MemberData(nameof(MlDsaSeeds))]
    public void MlDsa_FromSeed_PublicAndPrivateKeyHashes_AreStable(byte[] seed, string expectedPubHash, string expectedPrivHash)
    {
        var priv = MLDsaPrivateKeyParameters.FromSeed(MLDsaParameters.ml_dsa_65, seed);
        var pubBytes = priv.GetPublicKey().GetEncoded();
        var privBytes = priv
            .WithPreferredFormat(MLDsaPrivateKeyParameters.Format.SeedAndEncoding)
            .GetEncoded();

        Assert.Equal(1952, pubBytes.Length);
        var actualPubHash = Convert.ToHexString(SHA256.HashData(pubBytes)).ToLowerInvariant();
        var actualPrivHash = Convert.ToHexString(SHA256.HashData(privBytes)).ToLowerInvariant();

        if (expectedPubHash.StartsWith("PLACEHOLDER") || expectedPrivHash.StartsWith("PLACEHOLDER"))
        {
            Console.Error.WriteLine($"MlDsa seed[0]={seed[0]:x2} pubHash={actualPubHash} privHash={actualPrivHash}");
            return;
        }

        Assert.Equal(expectedPubHash, actualPubHash);
        Assert.Equal(expectedPrivHash, actualPrivHash);
    }

#if NET10_0_OR_GREATER
    [Theory]
    [MemberData(nameof(MlKemSeeds))]
    public void MlKem_FromSeed_BackendsProduceIdenticalPublicKey(byte[] seed, string expectedPubHash, string expectedPrivHash)
    {
        _ = expectedPubHash;
        _ = expectedPrivHash;

        if (!SystemMlKem.IsSupported)
        {
            return; // OS-level support unavailable; nothing to cross-check.
        }

        var bcPriv = MLKemPrivateKeyParameters.FromSeed(MLKemParameters.ml_kem_768, seed);
        var bcPub = bcPriv.GetPublicKey().GetEncoded();

        using var nativeKem = SystemMlKem.ImportPrivateSeed(SystemMlKemAlg.MLKem768, seed);
        var nativePub = nativeKem.ExportEncapsulationKey();

        Assert.Equal(bcPub, nativePub);
    }

    [Theory]
    [MemberData(nameof(MlDsaSeeds))]
    public void MlDsa_FromSeed_BackendsProduceIdenticalPublicKey(byte[] seed, string expectedPubHash, string expectedPrivHash)
    {
        _ = expectedPubHash;
        _ = expectedPrivHash;

        if (!SystemMlDsa.IsSupported)
        {
            return;
        }

        var bcPriv = MLDsaPrivateKeyParameters.FromSeed(MLDsaParameters.ml_dsa_65, seed);
        var bcPub = bcPriv.GetPublicKey().GetEncoded();

        using var nativeDsa = SystemMlDsa.ImportMLDsaPrivateSeed(SystemMlDsaAlg.MLDsa65, seed);
        var nativePub = nativeDsa.ExportMLDsaPublicKey();

        Assert.Equal(bcPub, nativePub);
    }
#endif
}
