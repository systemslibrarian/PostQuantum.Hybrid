using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using PostQuantum.Hybrid.Internal;

namespace PostQuantum.Hybrid;

/// <summary>
/// Hybrid Key Encapsulation Mechanism combining a classical Diffie-Hellman
/// primitive with a NIST-standardized post-quantum KEM. The derived 32-byte
/// shared secret is secure as long as <em>either</em> primitive remains
/// unbroken.
/// </summary>
/// <remarks>
/// The recommended default combination is X25519 + ML-KEM-768. The two
/// component shared secrets and both ciphertexts are fed into HKDF-SHA256 to
/// derive the final 32-byte shared secret.
/// </remarks>
public static class HybridKem
{
    /// <summary>The recommended default hybrid KEM algorithm combination.</summary>
    public static HybridKemAlgorithm Default => HybridKemAlgorithm.X25519MlKem768;

    /// <summary>Generates a fresh hybrid key pair using the default algorithm.</summary>
    public static HybridKemKeyPair GenerateKeyPair() => GenerateKeyPair(Default);

    /// <summary>Generates a fresh hybrid key pair using the specified algorithm.</summary>
    public static HybridKemKeyPair GenerateKeyPair(HybridKemAlgorithm algorithm)
    {
        EnsureSupported(algorithm);

        // Classical: X25519 via BouncyCastle.
        var keyGen = new X25519KeyPairGenerator();
        keyGen.Init(new X25519KeyGenerationParameters(new SecureRandom()));
        var bcPair = keyGen.GenerateKeyPair();
        var classicalPriv = ((X25519PrivateKeyParameters)bcPair.Private).GetEncoded();
        var classicalPub = ((X25519PublicKeyParameters)bcPair.Public).GetEncoded();

        // Post-quantum: ML-KEM-768 (native on .NET 10, BouncyCastle on .NET 8).
        var (pqPub, pqPriv) = MlKemBackend.GenerateKeyPair();

        var publicKey = new HybridKemPublicKey(algorithm, classicalPub, pqPub);
        var privateKey = new HybridKemPrivateKey(algorithm, classicalPriv, pqPriv);
        return new HybridKemKeyPair(publicKey, privateKey);
    }

    /// <summary>
    /// Encapsulates a fresh shared secret against a recipient's public key.
    /// Returns the ciphertext (to transmit) and the shared secret (to use locally).
    /// </summary>
    public static HybridKemEncapsulationResult Encapsulate(HybridKemPublicKey publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        EnsureSupported(publicKey.Algorithm);

        // Classical: generate ephemeral X25519 key pair and derive ss with recipient pub.
        var ephemeralGen = new X25519KeyPairGenerator();
        ephemeralGen.Init(new X25519KeyGenerationParameters(new SecureRandom()));
        var ephemeralPair = ephemeralGen.GenerateKeyPair();
        var ephemeralPriv = (X25519PrivateKeyParameters)ephemeralPair.Private;
        var ephemeralPub = (X25519PublicKeyParameters)ephemeralPair.Public;

        var recipientPub = new X25519PublicKeyParameters(publicKey.ClassicalKeySpan.ToArray(), 0);
        var agreement = new X25519Agreement();
        agreement.Init(ephemeralPriv);
        var classicalSecret = new byte[agreement.AgreementSize];
        agreement.CalculateAgreement(recipientPub, classicalSecret, 0);

        var classicalCiphertext = ephemeralPub.GetEncoded(); // ephemeral public IS the X25519 "ciphertext"

        // Post-quantum: ML-KEM-768 encapsulate.
        var pqCiphertext = new byte[AlgorithmSizes.MlKem768CiphertextBytes];
        var pqSecret = new byte[AlgorithmSizes.MlKem768SharedSecretBytes];
        MlKemBackend.Encapsulate(publicKey.PqKeySpan, pqCiphertext, pqSecret);

        var combined = KemCombiner.Combine(classicalSecret, pqSecret, classicalCiphertext, pqCiphertext);
        CryptographicOperations.ZeroMemory(classicalSecret);
        CryptographicOperations.ZeroMemory(pqSecret);

        var ciphertext = new HybridKemCiphertext(publicKey.Algorithm, classicalCiphertext, pqCiphertext);
        return new HybridKemEncapsulationResult(ciphertext, combined);
    }

    /// <summary>Recovers the 32-byte shared secret from a hybrid KEM ciphertext.</summary>
    public static byte[] Decapsulate(HybridKemPrivateKey privateKey, HybridKemCiphertext ciphertext)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(ciphertext);

        if (privateKey.Algorithm != ciphertext.Algorithm)
        {
            throw new PostQuantumHybridException(
                HybridFailureReason.AlgorithmMismatch,
                $"Algorithm mismatch: private key is {privateKey.Algorithm}, ciphertext is {ciphertext.Algorithm}.");
        }
        EnsureSupported(privateKey.Algorithm);

        // Classical: X25519 agreement between recipient private and ephemeral public.
        var recipientPriv = new X25519PrivateKeyParameters(privateKey.ClassicalKeySpan.ToArray(), 0);
        var ephemeralPub = new X25519PublicKeyParameters(ciphertext.ClassicalSpan.ToArray(), 0);
        var agreement = new X25519Agreement();
        agreement.Init(recipientPriv);
        var classicalSecret = new byte[agreement.AgreementSize];
        agreement.CalculateAgreement(ephemeralPub, classicalSecret, 0);

        // Post-quantum: ML-KEM decapsulate. Implicit rejection means malformed
        // ciphertexts yield pseudorandom secrets; the combined secret will simply
        // differ from the sender's and downstream decryption will fail.
        var pqSecret = new byte[AlgorithmSizes.MlKem768SharedSecretBytes];
        MlKemBackend.Decapsulate(privateKey.PqKeySpan, ciphertext.PqSpan, pqSecret);

        var combined = KemCombiner.Combine(classicalSecret, pqSecret, ciphertext.ClassicalSpan, ciphertext.PqSpan);
        CryptographicOperations.ZeroMemory(classicalSecret);
        CryptographicOperations.ZeroMemory(pqSecret);
        return combined;
    }

    /// <summary>Recovers the 32-byte shared secret from a serialized hybrid KEM ciphertext.</summary>
    public static byte[] Decapsulate(HybridKemPrivateKey privateKey, ReadOnlySpan<byte> ciphertextBytes)
        => Decapsulate(privateKey, HybridKemCiphertext.FromBytes(ciphertextBytes));

    private static void EnsureSupported(HybridKemAlgorithm algorithm)
    {
        if (algorithm != HybridKemAlgorithm.X25519MlKem768)
        {
            throw new PostQuantumHybridException(
                HybridFailureReason.UnsupportedAlgorithmId,
                $"Unsupported hybrid KEM algorithm: {algorithm}.");
        }
        if (!MlKemBackend.IsSupported)
        {
            throw new PostQuantumHybridException(
                HybridFailureReason.PrimitiveNotSupported,
                "ML-KEM is not supported on this platform.");
        }
    }
}
