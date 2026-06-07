using System.Security.Cryptography;

namespace PostQuantum.Hybrid.Envelopes;

/// <summary>
/// Misuse-resistant **signed + encrypted** envelope. Combines a
/// <see cref="HybridEnvelope"/> with a hybrid signature over the entire
/// envelope so the recipient can authenticate the sender and reject
/// any tampering before running KEM decapsulation.
/// </summary>
/// <remarks>
/// Wire format:
/// <code>
/// [ HybridEnvelope (variable) ] [ 3374B HybridSignature ]
/// </code>
/// <see cref="Open"/> verifies the signature FIRST, then unwraps the
/// inner anonymous envelope. Tampered envelopes are rejected without
/// ever touching the recipient's private key.
/// </remarks>
public static class SignedHybridEnvelope
{
    internal const int SignatureSize = 3374;

    /// <summary>
    /// Total per-envelope overhead, in bytes, on top of the plaintext.
    /// </summary>
    public const int OverheadBytes = HybridEnvelope.OverheadBytes + SignatureSize;

    /// <summary>
    /// Seals <paramref name="plaintext"/> against <paramref name="recipientPublicKey"/>
    /// and signs the result with <paramref name="senderSigningKey"/>.
    /// </summary>
    public static byte[] Seal(
        HybridSignaturePrivateKey senderSigningKey,
        HybridKemPublicKey recipientPublicKey,
        ReadOnlySpan<byte> plaintext)
    {
        ArgumentNullException.ThrowIfNull(senderSigningKey);
        ArgumentNullException.ThrowIfNull(recipientPublicKey);

        var inner = HybridEnvelope.Seal(recipientPublicKey, plaintext);
        var signature = HybridSignature.Sign(senderSigningKey, inner);

        var combined = new byte[inner.Length + signature.Length];
        inner.CopyTo(combined, 0);
        signature.CopyTo(combined, inner.Length);
        return combined;
    }

    /// <summary>
    /// Verifies the sender's signature, then opens the inner envelope.
    /// Throws on signature failure or any structural / AEAD failure.
    /// </summary>
    public static byte[] Open(
        HybridSignaturePublicKey senderVerificationKey,
        HybridKemPrivateKey recipientPrivateKey,
        ReadOnlySpan<byte> envelope)
    {
        ArgumentNullException.ThrowIfNull(senderVerificationKey);
        ArgumentNullException.ThrowIfNull(recipientPrivateKey);

        if (envelope.Length < OverheadBytes)
        {
            throw new PostQuantumHybridException(
                HybridFailureReason.InvalidLength,
                $"Signed envelope too short: need >= {OverheadBytes} bytes, got {envelope.Length}.");
        }

        var innerLen = envelope.Length - SignatureSize;
        var inner = envelope[..innerLen];
        var signature = envelope[innerLen..];

        if (!HybridSignature.Verify(senderVerificationKey, inner, signature))
        {
            // Generic message — do not leak which half failed.
            throw new CryptographicException(
                "Signed envelope verification failed; refusing to decrypt.");
        }

        return HybridEnvelope.Open(recipientPrivateKey, inner);
    }
}
