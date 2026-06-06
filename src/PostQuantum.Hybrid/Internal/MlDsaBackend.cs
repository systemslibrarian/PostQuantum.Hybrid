#if NET10_0_OR_GREATER
using System.Security.Cryptography;
#else
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
#endif

namespace PostQuantum.Hybrid.Internal;

/// <summary>
/// Abstraction over the ML-DSA-65 primitive. On .NET 10+ this uses the native
/// <c>System.Security.Cryptography.MLDsa</c> implementation; on .NET 8 it uses
/// BouncyCastle. Both backends produce wire-compatible artifacts (FIPS 204
/// "pure" ML-DSA with empty context).
/// </summary>
internal static class MlDsaBackend
{
    public static bool IsSupported
    {
#if NET10_0_OR_GREATER
        get => MLDsa.IsSupported;
#else
        get => true;
#endif
    }

    public static (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPair()
    {
#if NET10_0_OR_GREATER
        using var dsa = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        return (dsa.ExportMLDsaPublicKey(), dsa.ExportMLDsaPrivateKey());
#else
        var gen = new MLDsaKeyPairGenerator();
        gen.Init(new MLDsaKeyGenerationParameters(new SecureRandom(), MLDsaParameters.ml_dsa_65));
        var pair = gen.GenerateKeyPair();
        var pub = ((MLDsaPublicKeyParameters)pair.Public).GetEncoded();
        var priv = ((MLDsaPrivateKeyParameters)pair.Private)
            .WithPreferredFormat(MLDsaPrivateKeyParameters.Format.SeedAndEncoding)
            .GetEncoded();
        return (pub, priv);
#endif
    }

    public static byte[] SignData(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data)
    {
#if NET10_0_OR_GREATER
        using var dsa = MLDsa.ImportMLDsaPrivateKey(MLDsaAlgorithm.MLDsa65, privateKey);
        var sig = new byte[AlgorithmSizes.MlDsa65SignatureBytes];
        dsa.SignData(data, sig, context: default);
        return sig;
#else
        var priv = MLDsaPrivateKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_65, privateKey.ToArray());
        var signer = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: false);
        signer.Init(forSigning: true, priv);
        signer.BlockUpdate(data);
        return signer.GenerateSignature();
#endif
    }

    public static bool VerifyData(
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature)
    {
#if NET10_0_OR_GREATER
        using var dsa = MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa65, publicKey);
        return dsa.VerifyData(data, signature, context: default);
#else
        var pub = MLDsaPublicKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_65, publicKey.ToArray());
        var verifier = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: false);
        verifier.Init(forSigning: false, pub);
        verifier.BlockUpdate(data);
        return verifier.VerifySignature(signature.ToArray());
#endif
    }
}
