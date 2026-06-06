using System.Security.Cryptography;
using System.Text;

namespace PostQuantum.Hybrid.Internal;

/// <summary>
/// Combines the two component shared secrets of a hybrid KEM into a single
/// 32-byte secret. Uses HKDF-SHA256 with a transcript that binds both
/// ciphertexts, so the derived secret depends on the full exchange and not
/// just the individual KEM shared secrets.
/// </summary>
internal static class KemCombiner
{
    private static readonly byte[] InfoPrefix =
        Encoding.ASCII.GetBytes("PostQuantum.Hybrid v1 KEM X25519-MLKEM768");

    public static byte[] Combine(
        ReadOnlySpan<byte> classicalSecret,
        ReadOnlySpan<byte> pqSecret,
        ReadOnlySpan<byte> classicalCiphertext,
        ReadOnlySpan<byte> pqCiphertext)
    {
        Span<byte> ikm = stackalloc byte[classicalSecret.Length + pqSecret.Length];
        classicalSecret.CopyTo(ikm);
        pqSecret.CopyTo(ikm[classicalSecret.Length..]);

        byte[] info = new byte[InfoPrefix.Length + classicalCiphertext.Length + pqCiphertext.Length];
        InfoPrefix.CopyTo(info, 0);
        classicalCiphertext.CopyTo(info.AsSpan(InfoPrefix.Length));
        pqCiphertext.CopyTo(info.AsSpan(InfoPrefix.Length + classicalCiphertext.Length));

        var output = new byte[AlgorithmSizes.HybridSharedSecretBytes];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, output, salt: default, info: info);
        CryptographicOperations.ZeroMemory(ikm);
        return output;
    }
}
