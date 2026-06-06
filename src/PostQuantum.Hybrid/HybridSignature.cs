using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using PostQuantum.Hybrid.Internal;

namespace PostQuantum.Hybrid;

/// <summary>
/// Hybrid digital signatures combining a classical EdDSA primitive with a
/// NIST-standardized post-quantum signature scheme. A signature is valid only
/// if both component signatures verify, so forgery requires breaking
/// <em>both</em> schemes.
/// </summary>
/// <remarks>
/// The recommended default combination is Ed25519 + ML-DSA-65. Both schemes
/// sign the user-provided message bytes directly (each does its own internal
/// hashing); the resulting signatures are concatenated in a versioned wire
/// format.
/// </remarks>
public static class HybridSignature
{
    /// <summary>The recommended default hybrid signature algorithm combination.</summary>
    public static HybridSignatureAlgorithm Default => HybridSignatureAlgorithm.Ed25519MlDsa65;

    /// <summary>Generates a fresh hybrid signature key pair using the default algorithm.</summary>
    public static HybridSignatureKeyPair GenerateKeyPair() => GenerateKeyPair(Default);

    /// <summary>Generates a fresh hybrid signature key pair using the specified algorithm.</summary>
    public static HybridSignatureKeyPair GenerateKeyPair(HybridSignatureAlgorithm algorithm)
    {
        EnsureSupported(algorithm);

        // Classical: Ed25519 via BouncyCastle.
        var keyGen = new Ed25519KeyPairGenerator();
        keyGen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var bcPair = keyGen.GenerateKeyPair();
        var classicalPriv = ((Ed25519PrivateKeyParameters)bcPair.Private).GetEncoded();
        var classicalPub = ((Ed25519PublicKeyParameters)bcPair.Public).GetEncoded();

        // Post-quantum: ML-DSA-65 (native on .NET 10, BouncyCastle on .NET 8).
        var (pqPub, pqPriv) = MlDsaBackend.GenerateKeyPair();

        var publicKey = new HybridSignaturePublicKey(algorithm, classicalPub, pqPub);
        var privateKey = new HybridSignaturePrivateKey(algorithm, classicalPriv, pqPriv);
        return new HybridSignatureKeyPair(publicKey, privateKey);
    }

    /// <summary>Signs the supplied data, producing a concatenated hybrid signature.</summary>
    public static byte[] Sign(HybridSignaturePrivateKey privateKey, ReadOnlySpan<byte> data)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        EnsureSupported(privateKey.Algorithm);

        // Classical: Ed25519.
        var bcPriv = new Ed25519PrivateKeyParameters(privateKey.ClassicalKeySpan.ToArray(), 0);
        var signer = new Ed25519Signer();
        signer.Init(forSigning: true, bcPriv);
        var dataArray = data.ToArray();
        signer.BlockUpdate(dataArray, 0, dataArray.Length);
        var classicalSig = signer.GenerateSignature();

        // Post-quantum: ML-DSA-65 with empty context (FIPS 204 "pure" ML-DSA).
        var pqSig = MlDsaBackend.SignData(privateKey.PqKeySpan, data);

        var result = new byte[AlgorithmSizes.HybridSignatureBytes];
        result[0] = (byte)privateKey.Algorithm;
        classicalSig.CopyTo(result.AsSpan(1));
        pqSig.CopyTo(result.AsSpan(1 + AlgorithmSizes.Ed25519SignatureBytes));
        return result;
    }

    /// <summary>Verifies a hybrid signature. Returns true only if both component signatures are valid.</summary>
    public static bool Verify(
        HybridSignaturePublicKey publicKey,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        EnsureSupported(publicKey.Algorithm);

        if (signature.Length != AlgorithmSizes.HybridSignatureBytes)
        {
            return false;
        }
        if (signature[0] != (byte)publicKey.Algorithm)
        {
            return false;
        }

        var classicalSig = signature.Slice(1, AlgorithmSizes.Ed25519SignatureBytes);
        var pqSig = signature.Slice(1 + AlgorithmSizes.Ed25519SignatureBytes, AlgorithmSizes.MlDsa65SignatureBytes);

        // Classical: Ed25519.
        var bcPub = new Ed25519PublicKeyParameters(publicKey.ClassicalKeySpan.ToArray(), 0);
        var verifier = new Ed25519Signer();
        verifier.Init(forSigning: false, bcPub);
        var dataArray = data.ToArray();
        verifier.BlockUpdate(dataArray, 0, dataArray.Length);
        bool classicalOk = verifier.VerifySignature(classicalSig.ToArray());

        // Post-quantum: ML-DSA-65.
        bool pqOk = MlDsaBackend.VerifyData(publicKey.PqKeySpan, data, pqSig);

        return classicalOk && pqOk;
    }

    private static void EnsureSupported(HybridSignatureAlgorithm algorithm)
    {
        if (algorithm != HybridSignatureAlgorithm.Ed25519MlDsa65)
        {
            throw new CryptographicException($"Unsupported hybrid signature algorithm: {algorithm}.");
        }
        if (!MlDsaBackend.IsSupported)
        {
            throw new PlatformNotSupportedException("ML-DSA is not supported on this platform.");
        }
    }
}
