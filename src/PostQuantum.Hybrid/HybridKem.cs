using System.Diagnostics.CodeAnalysis;
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

        var recipientPub = new X25519PublicKeyParameters(publicKey.ClassicalKeySpan);
        var agreement = new X25519Agreement();
        agreement.Init(ephemeralPriv);
        var classicalSecret = new byte[agreement.AgreementSize];
        agreement.CalculateAgreement(recipientPub, classicalSecret, 0);

        var classicalCiphertext = ephemeralPub.GetEncoded(); // ephemeral public IS the X25519 "ciphertext"

        // Post-quantum: ML-KEM-768 encapsulate.
        var pqCiphertext = new byte[AlgorithmSizes.MlKem768CiphertextBytes];
        using var pqSecret = new SecureBuffer(AlgorithmSizes.MlKem768SharedSecretBytes);
        MlKemBackend.Encapsulate(publicKey.PqKeySpan, pqCiphertext, pqSecret.Span);

        var combiner = KemCombiner.ForAlgorithm(publicKey.Algorithm);
        var combined = new byte[AlgorithmSizes.HybridSharedSecretBytes];
        combiner.Combine(
            classicalSecret, pqSecret.ReadOnlySpan,
            classicalCiphertext, pqCiphertext,
            publicKey.ClassicalKeySpan,
            combined);
        CryptographicOperations.ZeroMemory(classicalSecret);

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
            throw new InvalidCiphertextException(
                HybridFailureReason.AlgorithmMismatch,
                $"Algorithm mismatch: private key is {privateKey.Algorithm}, ciphertext is {ciphertext.Algorithm}.");
        }
        EnsureSupported(privateKey.Algorithm);

        // Classical: X25519 agreement between recipient private and ephemeral public.
        // Materialize the recipient's seed into a SecureBuffer that zeroes
        // itself on scope exit, even if the agreement throws. We also need
        // the recipient's classical PUBLIC key for the X-Wing combiner
        // (algorithm-id 0x02 binds pk_X into the SHA3 input); derive it
        // from the recipient private inside the same secure scope.
        var classicalSecret = new byte[AlgorithmSizes.X25519SharedSecretBytes];
        var recipientClassicalPub = new byte[AlgorithmSizes.X25519PublicKeyBytes];
        using (var classicalSeed = new SecureBuffer(privateKey.ClassicalKeySpan.Length))
        {
            privateKey.ClassicalKeySpan.CopyTo(classicalSeed.Span);
            var recipientPriv = new X25519PrivateKeyParameters(classicalSeed.ReadOnlySpan);
            var ephemeralPub = new X25519PublicKeyParameters(ciphertext.ClassicalSpan);
            var agreement = new X25519Agreement();
            agreement.Init(recipientPriv);
            agreement.CalculateAgreement(ephemeralPub, classicalSecret, 0);
            recipientPriv.GeneratePublicKey().Encode(recipientClassicalPub, 0);
        }

        // Post-quantum: ML-KEM decapsulate. Implicit rejection means malformed
        // ciphertexts yield pseudorandom secrets; the combined secret will simply
        // differ from the sender's and downstream decryption will fail.
        using var pqSecret = new SecureBuffer(AlgorithmSizes.MlKem768SharedSecretBytes);
        MlKemBackend.Decapsulate(privateKey.PqKeySpan, ciphertext.PqSpan, pqSecret.Span);

        var combiner = KemCombiner.ForAlgorithm(privateKey.Algorithm);
        var combined = new byte[AlgorithmSizes.HybridSharedSecretBytes];
        combiner.Combine(
            classicalSecret, pqSecret.ReadOnlySpan,
            ciphertext.ClassicalSpan, ciphertext.PqSpan,
            recipientClassicalPub,
            combined);
        CryptographicOperations.ZeroMemory(classicalSecret);
        return combined;
    }

    /// <summary>Recovers the 32-byte shared secret from a serialized hybrid KEM ciphertext.</summary>
    public static byte[] Decapsulate(HybridKemPrivateKey privateKey, ReadOnlySpan<byte> ciphertextBytes)
        => Decapsulate(privateKey, HybridKemCiphertext.FromBytes(ciphertextBytes));

    /// <summary>
    /// Non-throwing counterpart to <see cref="Decapsulate(HybridKemPrivateKey, HybridKemCiphertext)"/>.
    /// Returns <see langword="true"/> with the 32-byte secret in
    /// <paramref name="sharedSecret"/> on success; returns
    /// <see langword="false"/> with <paramref name="sharedSecret"/> set to
    /// <see langword="null"/> on parse / algorithm-mismatch failures. Does
    /// <em>not</em> distinguish FIPS-203 implicit-rejection outcomes: a
    /// malformed ML-KEM ciphertext returns <see langword="true"/> with a
    /// pseudorandom secret, exactly as the throwing variant would.
    /// </summary>
    public static bool TryDecapsulate(
        HybridKemPrivateKey privateKey,
        HybridKemCiphertext ciphertext,
        [NotNullWhen(true)] out byte[]? sharedSecret)
    {
        try { sharedSecret = Decapsulate(privateKey, ciphertext); return true; }
        catch (Exception ex) when (ex is PostQuantumHybridException or CryptographicException or ArgumentNullException or ObjectDisposedException)
        { sharedSecret = null; return false; }
    }

    /// <summary>
    /// Non-throwing counterpart to <see cref="Decapsulate(HybridKemPrivateKey, ReadOnlySpan{byte})"/>.
    /// </summary>
    public static bool TryDecapsulate(
        HybridKemPrivateKey privateKey,
        ReadOnlySpan<byte> ciphertextBytes,
        [NotNullWhen(true)] out byte[]? sharedSecret)
    {
        if (!HybridKemCiphertext.TryFromBytes(ciphertextBytes, out var ciphertext))
        {
            sharedSecret = null;
            return false;
        }
        return TryDecapsulate(privateKey, ciphertext, out sharedSecret);
    }

    private static void EnsureSupported(HybridKemAlgorithm algorithm)
    {
        switch (algorithm)
        {
            case HybridKemAlgorithm.X25519MlKem768:
            case HybridKemAlgorithm.X25519MlKem768XWing:
                // ML-KEM is always available via the BouncyCastle fallback;
                // MlKemBackend prefers the native .NET 10 implementation when
                // MLKem.IsSupported is true and otherwise transparently uses BC.
                return;
            default:
                throw new PostQuantumHybridException(
                    HybridFailureReason.UnsupportedAlgorithmId,
                    $"Unsupported hybrid KEM algorithm: {algorithm}.");
        }
    }
}
