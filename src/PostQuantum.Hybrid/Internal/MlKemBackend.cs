#if NET10_0_OR_GREATER
using System.Security.Cryptography;
#else
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
#endif

namespace PostQuantum.Hybrid.Internal;

/// <summary>
/// Abstraction over the ML-KEM-768 primitive. On .NET 10+ this uses the
/// native <c>System.Security.Cryptography.MLKem</c> implementation; on .NET 8
/// it uses BouncyCastle. Both backends produce wire-compatible artifacts
/// (FIPS 203).
/// </summary>
internal static class MlKemBackend
{
    public static bool IsSupported
    {
#if NET10_0_OR_GREATER
        get => MLKem.IsSupported;
#else
        get => true;
#endif
    }

    public static (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPair()
    {
#if NET10_0_OR_GREATER
        using var kem = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
        return (kem.ExportEncapsulationKey(), kem.ExportDecapsulationKey());
#else
        var gen = new MLKemKeyPairGenerator();
        gen.Init(new MLKemKeyGenerationParameters(new SecureRandom(), MLKemParameters.ml_kem_768));
        var pair = gen.GenerateKeyPair();
        var pub = ((MLKemPublicKeyParameters)pair.Public).GetEncoded();
        var priv = ((MLKemPrivateKeyParameters)pair.Private)
            .WithPreferredFormat(MLKemPrivateKeyParameters.Format.SeedAndEncoding)
            .GetEncoded();
        return (pub, priv);
#endif
    }

    public static void Encapsulate(
        ReadOnlySpan<byte> publicKey,
        Span<byte> ciphertext,
        Span<byte> sharedSecret)
    {
#if NET10_0_OR_GREATER
        using var kem = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, publicKey);
        kem.Encapsulate(ciphertext, sharedSecret);
#else
        var pub = MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, publicKey.ToArray());
        var enc = new MLKemEncapsulator(MLKemParameters.ml_kem_768);
        enc.Init(pub);
        enc.Encapsulate(ciphertext, sharedSecret);
#endif
    }

    public static void Decapsulate(
        ReadOnlySpan<byte> privateKey,
        ReadOnlySpan<byte> ciphertext,
        Span<byte> sharedSecret)
    {
#if NET10_0_OR_GREATER
        using var kem = MLKem.ImportDecapsulationKey(MLKemAlgorithm.MLKem768, privateKey);
        kem.Decapsulate(ciphertext, sharedSecret);
#else
        var priv = MLKemPrivateKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, privateKey.ToArray());
        var dec = new MLKemDecapsulator(MLKemParameters.ml_kem_768);
        dec.Init(priv);
        dec.Decapsulate(ciphertext, sharedSecret);
#endif
    }
}
