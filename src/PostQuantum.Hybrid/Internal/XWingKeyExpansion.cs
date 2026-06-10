using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Digests;

namespace PostQuantum.Hybrid.Internal;

/// <summary>
/// IETF X-Wing decapsulation-key expansion
/// (draft-connolly-cfrg-xwing-kem, see ADR 0015):
/// <code>
/// expanded = SHAKE-256(seed, 96)
/// (pk_M, sk_M) = ML-KEM-768.KeyGen_internal(expanded[0:64])   // d || z
/// sk_X = expanded[64:96]
/// </code>
/// SHAKE-256 comes from BouncyCastle so behavior is identical on every
/// TFM and host platform — the BCL's SHAKE support cannot be relied on
/// across the support matrix.
/// </summary>
internal static class XWingKeyExpansion
{
    /// <summary>
    /// Expands a 32-byte X-Wing seed into the 64-byte ML-KEM-768 keygen
    /// seed (<c>d || z</c>) and the 32-byte X25519 private key. Both
    /// output spans receive sensitive material; callers own zeroization.
    /// </summary>
    public static void Expand(ReadOnlySpan<byte> seed, Span<byte> mlKemSeedDz, Span<byte> x25519PrivateKey)
    {
        if (seed.Length != AlgorithmSizes.XWingSeedBytes)
        {
            throw new ArgumentException(
                $"X-Wing seed must be {AlgorithmSizes.XWingSeedBytes} bytes.", nameof(seed));
        }
        if (mlKemSeedDz.Length != AlgorithmSizes.MlKem768KeyGenSeedBytes)
        {
            throw new ArgumentException(
                $"mlKemSeedDz must be {AlgorithmSizes.MlKem768KeyGenSeedBytes} bytes.", nameof(mlKemSeedDz));
        }
        if (x25519PrivateKey.Length != AlgorithmSizes.X25519PrivateKeyBytes)
        {
            throw new ArgumentException(
                $"x25519PrivateKey must be {AlgorithmSizes.X25519PrivateKeyBytes} bytes.", nameof(x25519PrivateKey));
        }

        var shake = new ShakeDigest(256);
        var seedBuf = seed.ToArray();
        Span<byte> expanded = stackalloc byte[AlgorithmSizes.XWingExpandedBytes];
        try
        {
            shake.BlockUpdate(seedBuf, 0, seedBuf.Length);
            shake.OutputFinal(expanded);
            expanded[..AlgorithmSizes.MlKem768KeyGenSeedBytes].CopyTo(mlKemSeedDz);
            expanded[AlgorithmSizes.MlKem768KeyGenSeedBytes..].CopyTo(x25519PrivateKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seedBuf);
            CryptographicOperations.ZeroMemory(expanded);
        }
    }
}
