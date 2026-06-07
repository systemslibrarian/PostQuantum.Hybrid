using System.Security.Cryptography;
using System.Text;

namespace PostQuantum.Hybrid.AspNetCore;

/// <summary>
/// Internal envelope format used by <see cref="HybridEnvelopeDataProtector"/>.
/// Mirrors <c>PostQuantum.Hybrid.Envelopes.HybridEnvelope</c> but stays
/// inside this package so the AspNetCore extension does not take a hard
/// dependency on the Envelopes package. The on-the-wire layout matches
/// where the purpose chain is empty (so consumers can switch between
/// the two paths without re-encrypting).
/// </summary>
/// <remarks>
/// Wire format (1150 bytes overhead):
/// <code>
/// [ 1B  version = 0x01 ]
/// [ 1121B hybrid KEM ciphertext ]
/// [ 12B nonce ]
/// [ 16B AES-GCM tag ]
/// [ N    AES-GCM ciphertext ]
/// </code>
/// AEAD <c>associatedData</c> binds both the KEM ciphertext and the
/// caller's purpose string, so a payload protected for purpose A
/// cannot be unprotected for purpose B.
/// </remarks>
internal static class EnvelopeFormat
{
    private const byte Version = 0x01;
    private const int VersionSize = 1;
    private const int KemCiphertextSize = 1121;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int OverheadBytes = VersionSize + KemCiphertextSize + NonceSize + TagSize;

    private static readonly byte[] HkdfInfoPrefix =
        Encoding.ASCII.GetBytes("PostQuantum.Hybrid.AspNetCore v1 IDataProtector AES-256-GCM");

    public static byte[] Seal(HybridKemPublicKey recipient, ReadOnlySpan<byte> plaintext, string purpose)
    {
        using var encapsulation = HybridKem.Encapsulate(recipient);
        var kemCt = encapsulation.Ciphertext.ToBytes();
        var aesKey = DeriveAesKey(encapsulation.SharedSecret, kemCt);

        var envelope = new byte[OverheadBytes + plaintext.Length];
        envelope[0] = Version;
        kemCt.CopyTo(envelope.AsSpan(VersionSize));

        var nonceOffset = VersionSize + KemCiphertextSize;
        var tagOffset = nonceOffset + NonceSize;
        var ctOffset = tagOffset + TagSize;

        RandomNumberGenerator.Fill(envelope.AsSpan(nonceOffset, NonceSize));
        var aad = BuildAad(envelope.AsSpan(VersionSize, KemCiphertextSize), purpose);
        try
        {
            using var aes = new AesGcm(aesKey, TagSize);
            aes.Encrypt(
                envelope.AsSpan(nonceOffset, NonceSize),
                plaintext,
                envelope.AsSpan(ctOffset, plaintext.Length),
                envelope.AsSpan(tagOffset, TagSize),
                associatedData: aad);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aesKey);
        }
        return envelope;
    }

    public static byte[] Open(HybridKemPrivateKey recipient, ReadOnlySpan<byte> envelope, string purpose)
    {
        if (envelope.Length < OverheadBytes)
        {
            throw new PostQuantumHybridException(
                HybridFailureReason.InvalidLength,
                $"Protected payload too short: need >= {OverheadBytes} bytes, got {envelope.Length}.");
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
        var ct = envelope[OverheadBytes..];

        var sharedSecret = HybridKem.Decapsulate(recipient, kemCt);
        try
        {
            var aesKey = DeriveAesKey(sharedSecret, kemCt);
            try
            {
                var plaintext = new byte[ct.Length];
                var aad = BuildAad(kemCt, purpose);
                using var aes = new AesGcm(aesKey, TagSize);
                aes.Decrypt(nonce, ct, tag, plaintext, associatedData: aad);
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

    private static byte[] DeriveAesKey(ReadOnlySpan<byte> sharedSecret, ReadOnlySpan<byte> kemCiphertext)
    {
        var info = new byte[HkdfInfoPrefix.Length + kemCiphertext.Length];
        HkdfInfoPrefix.CopyTo(info, 0);
        kemCiphertext.CopyTo(info.AsSpan(HkdfInfoPrefix.Length));
        var key = new byte[32];
        HKDF.Expand(HashAlgorithmName.SHA256, sharedSecret, key, info);
        return key;
    }

    private static byte[] BuildAad(ReadOnlySpan<byte> kemCiphertext, string purpose)
    {
        var purposeBytes = Encoding.UTF8.GetBytes(purpose);
        var aad = new byte[kemCiphertext.Length + purposeBytes.Length];
        kemCiphertext.CopyTo(aad);
        purposeBytes.CopyTo(aad.AsSpan(kemCiphertext.Length));
        return aad;
    }
}
