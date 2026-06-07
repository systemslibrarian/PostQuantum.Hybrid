using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Xunit;

namespace PostQuantum.Hybrid.Tests;

/// <summary>
/// FIPS-203 / FIPS-204 conformance regression tests. Uses BouncyCastle's
/// <c>FromSeed</c> to derive ML-KEM-768 and ML-DSA-65 key material
/// deterministically from a fixed seed, then asserts the SHA-256 of the
/// resulting public key bytes matches a pinned expected value.
///
/// On net10.0 we additionally re-derive the same key pair via the native
/// backend (where seed-based derivation is available) and confirm
/// bit-equality. Together, these prove both backends agree with each
/// other and with their own historical behavior.
/// </summary>
public class DeterministicKeyGenerationTests
{
    // 64-byte (z || d) seed for ML-KEM-768.
    private static readonly byte[] MlKemSeed = Convert.FromHexString(
        "0001020304050607" + "08090a0b0c0d0e0f" +
        "1011121314151617" + "18191a1b1c1d1e1f" +
        "2021222324252627" + "28292a2b2c2d2e2f" +
        "3031323334353637" + "38393a3b3c3d3e3f");

    // 32-byte (xi) seed for ML-DSA-65.
    private static readonly byte[] MlDsaSeed = Convert.FromHexString(
        "404142434445464748494a4b4c4d4e4f" + "505152535455565758595a5b5c5d5e5f");

    [Fact]
    public void MlKem768_FromSeed_BC_PublicKeyHashIsStable()
    {
        var priv = MLKemPrivateKeyParameters.FromSeed(MLKemParameters.ml_kem_768, MlKemSeed);
        var pub = priv.GetPublicKey().GetEncoded();
        Assert.Equal(1184, pub.Length);

        var sha = SHA256.HashData(pub);
        Assert.Equal(
            "0b7934c83125c788995e2ba6bd761e33046b3e40571be53e023309a29f398cc9",
            Convert.ToHexString(sha).ToLowerInvariant());
    }

    [Fact]
    public void MlDsa65_FromSeed_BC_PublicKeyHashIsStable()
    {
        var priv = MLDsaPrivateKeyParameters.FromSeed(MLDsaParameters.ml_dsa_65, MlDsaSeed);
        var pub = priv.GetPublicKey().GetEncoded();
        Assert.Equal(1952, pub.Length);

        var sha = SHA256.HashData(pub);
        Assert.Equal(
            "ddf723ba0cc75408d1a3a8dc48f8302bfc25bd2cacf9374c28d861deea3a7184",
            Convert.ToHexString(sha).ToLowerInvariant());
    }

#if NET10_0_OR_GREATER
    [Fact]
    public void MlKem768_FromSeed_BackendsAgreeOnPublicKey()
    {
        // Gate on actual native availability: on Linux distros whose OpenSSL
        // doesn't ship ML-KEM, MLKem.IsSupported is false and the library
        // transparently uses BouncyCastle for both backends — there is nothing
        // to cross-check.
        if (!MLKem.IsSupported)
        {
            return;
        }

        // BC backend.
        var bcPriv = MLKemPrivateKeyParameters.FromSeed(MLKemParameters.ml_kem_768, MlKemSeed);
        var bcPub = bcPriv.GetPublicKey().GetEncoded();

        // Native backend (.NET 10).
        using var nativeKem = MLKem.ImportPrivateSeed(MLKemAlgorithm.MLKem768, MlKemSeed);
        var nativePub = nativeKem.ExportEncapsulationKey();

        Assert.Equal(bcPub, nativePub);
    }

    [Fact]
    public void MlDsa65_FromSeed_BackendsAgreeOnPublicKey()
    {
        if (!MLDsa.IsSupported)
        {
            return;
        }

        var bcPriv = MLDsaPrivateKeyParameters.FromSeed(MLDsaParameters.ml_dsa_65, MlDsaSeed);
        var bcPub = bcPriv.GetPublicKey().GetEncoded();

        using var nativeDsa = MLDsa.ImportMLDsaPrivateSeed(MLDsaAlgorithm.MLDsa65, MlDsaSeed);
        var nativePub = nativeDsa.ExportMLDsaPublicKey();

        Assert.Equal(bcPub, nativePub);
    }
#endif
}
