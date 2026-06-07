using System.Security.Cryptography;
using System.Text;

namespace PostQuantum.Hybrid.Envelopes;

/// <summary>
/// Misuse-resistant **anonymous** encrypted envelope. Combines hybrid KEM
/// with AES-256-GCM in one call so callers never have to wire HKDF, nonce
/// generation, AEAD binding, or buffer zeroization themselves.
/// </summary>
/// <remarks>
/// Wire format (versioned, fixed-overhead 1150 bytes):
/// <code>
/// [ 1B version (0x01) ] [ 1121B KEM ciphertext ] [ 12B nonce ]
/// [ 16B AES-GCM tag ] [ N bytes ciphertext ]
/// </code>
/// The KEM ciphertext is bound into the AEAD as <c>associatedData</c>.
/// Anonymous envelopes do not authenticate the sender — anyone holding
/// the recipient's public key can produce one. Use
/// <see cref="SignedHybridEnvelope"/> when sender authentication is
/// required.
/// </remarks>
public static class HybridEnvelope
{
    internal const byte Version = 0x01;
    internal const int VersionSize = 1;
    internal const int KemCiphertextSize = 1121;
    internal const int NonceSize = 12;
    internal const int TagSize = 16;

    /// <summary>Total per-envelope overhead, in bytes, around the plaintext.</summary>
    public const int OverheadBytes = VersionSize + KemCiphertextSize + NonceSize + TagSize;

    private static readonly byte[] HkdfInfoPrefix =
        Encoding.ASCII.GetBytes("PostQuantum.Hybrid.Envelopes v1 AES-256-GCM");

    /// <summary>
    /// Seals <paramref name="plaintext"/> against <paramref name="recipientPublicKey"/>.
    /// Returns a self-contained envelope blob suitable for storage or transmission.
    /// </summary>
    public static byte[] Seal(HybridKemPublicKey recipientPublicKey, ReadOnlySpan<byte> plaintext)
    {
        ArgumentNullException.ThrowIfNull(recipientPublicKey);

        using var encapsulation = HybridKem.Encapsulate(recipientPublicKey);
        var kemCt = encapsulation.Ciphertext.ToBytes();
        var aesKey = DeriveAesKey(encapsulation.SharedSecret, kemCt);

        var envelope = new byte[OverheadBytes + plaintext.Length];
        envelope[0] = Version;
        kemCt.CopyTo(envelope.AsSpan(VersionSize));

        var nonceOffset = VersionSize + KemCiphertextSize;
        var tagOffset = nonceOffset + NonceSize;
        var ctOffset = tagOffset + TagSize;

        RandomNumberGenerator.Fill(envelope.AsSpan(nonceOffset, NonceSize));
        try
        {
            using var aes = new AesGcm(aesKey, TagSize);
            aes.Encrypt(
                envelope.AsSpan(nonceOffset, NonceSize),
                plaintext,
                envelope.AsSpan(ctOffset, plaintext.Length),
                envelope.AsSpan(tagOffset, TagSize),
                associatedData: envelope.AsSpan(VersionSize, KemCiphertextSize));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aesKey);
        }
        return envelope;
    }

    /// <summary>
    /// Opens an envelope produced by <see cref="Seal"/>. Throws
    /// <see cref="CryptographicException"/> (or a derived type) on any
    /// authentication failure or malformed input.
    /// </summary>
    public static byte[] Open(HybridKemPrivateKey recipientPrivateKey, ReadOnlySpan<byte> envelope)
    {
        ArgumentNullException.ThrowIfNull(recipientPrivateKey);

        if (envelope.Length < OverheadBytes)
        {
            throw new PostQuantumHybridException(
                HybridFailureReason.InvalidLength,
                $"Envelope too short: need >= {OverheadBytes} bytes, got {envelope.Length}.");
        }
        if (envelope[0] != Version)
        {
            throw new PostQuantumHybridException(
                HybridFailureReason.UnsupportedAlgorithmId,
                $"Unsupported envelope version: 0x{envelope[0]:X2}.");
        }

        var kemCt = envelope.Slice(VersionSize, KemCiphertextSize);
        var nonce = envelope.Slice(VersionSize + KemCiphertextSize, NonceSize);
        var tag = envelope.Slice(VersionSize + KemCiphertextSize + NonceSize, TagSize);
        var ct = envelope[(OverheadBytes)..];

        var sharedSecret = HybridKem.Decapsulate(recipientPrivateKey, kemCt);
        try
        {
            var aesKey = DeriveAesKey(sharedSecret, kemCt);
            try
            {
                var plaintext = new byte[ct.Length];
                using var aes = new AesGcm(aesKey, TagSize);
                aes.Decrypt(nonce, ct, tag, plaintext, associatedData: kemCt);
                return plaintext;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(aesKey);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }

    internal static byte[] DeriveAesKey(ReadOnlySpan<byte> sharedSecret, ReadOnlySpan<byte> kemCiphertext)
    {
        var info = new byte[HkdfInfoPrefix.Length + kemCiphertext.Length];
        HkdfInfoPrefix.CopyTo(info, 0);
        kemCiphertext.CopyTo(info.AsSpan(HkdfInfoPrefix.Length));

        var key = new byte[32];
        HKDF.Expand(HashAlgorithmName.SHA256, sharedSecret, key, info);
        return key;
    }
}
