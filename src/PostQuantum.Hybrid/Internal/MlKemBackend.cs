#if NET10_0_OR_GREATER
using System.Security.Cryptography;
#endif
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace PostQuantum.Hybrid.Internal;

/// <summary>
/// Abstraction over the ML-KEM-768 primitive. On .NET 10+ the backend
/// prefers the native <c>System.Security.Cryptography.MLKem</c>
/// implementation when the underlying OS (specifically the OpenSSL
/// provider .NET binds to) actually exposes ML-KEM, and otherwise falls
/// back to BouncyCastle. .NET 8 always uses BouncyCastle. Both backends
/// produce wire-compatible artifacts (FIPS 203).
/// </summary>
internal static class MlKemBackend
{
    private static bool UseNative
    {
#if NET10_0_OR_GREATER
        get => MLKem.IsSupported;
#else
        get => false;
#endif
    }

    /// <summary>
    /// Always <c>true</c>: ML-KEM is supported via the BouncyCastle fallback
    /// on every TFM the library targets. Retained for API compatibility.
    /// </summary>
    public static bool IsSupported => true;

    public static (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPair()
    {
#if NET10_0_OR_GREATER
        if (UseNative)
        {
            using var kem = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
            return (kem.ExportEncapsulationKey(), kem.ExportDecapsulationKey());
        }
#endif
        var gen = new MLKemKeyPairGenerator();
        gen.Init(new MLKemKeyGenerationParameters(new SecureRandom(), MLKemParameters.ml_kem_768));
        var pair = gen.GenerateKeyPair();
        var pub = ((MLKemPublicKeyParameters)pair.Public).GetEncoded();
        var priv = ((MLKemPrivateKeyParameters)pair.Private)
            .WithPreferredFormat(MLKemPrivateKeyParameters.Format.SeedAndEncoding)
            .GetEncoded();
        return (pub, priv);
    }

    public static void Encapsulate(
        ReadOnlySpan<byte> publicKey,
        Span<byte> ciphertext,
        Span<byte> sharedSecret)
    {
#if NET10_0_OR_GREATER
        if (UseNative)
        {
            using var kem = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, publicKey);
            kem.Encapsulate(ciphertext, sharedSecret);
            return;
        }
#endif
        var pub = MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, publicKey.ToArray());
        var enc = new MLKemEncapsulator(MLKemParameters.ml_kem_768);
        enc.Init(pub);
        enc.Encapsulate(ciphertext, sharedSecret);
    }

    /// <summary>
    /// Derives the 1184-byte ML-KEM-768 encapsulation key from a 64-byte
    /// FIPS 203 keygen seed (<c>d || z</c>). Used by the X-Wing
    /// (algorithm-id 0x03) seed-expansion flow.
    /// </summary>
    public static byte[] PublicKeyFromSeed(ReadOnlySpan<byte> seedDz)
    {
#if NET10_0_OR_GREATER
        if (UseNative)
        {
            using var kem = MLKem.ImportPrivateSeed(MLKemAlgorithm.MLKem768, seedDz);
            return kem.ExportEncapsulationKey();
        }
#endif
        var seed = seedDz.ToArray();
        try
        {
            return MLKemPrivateKeyParameters
                .FromSeed(MLKemParameters.ml_kem_768, seed)
                .GetPublicKeyEncoded();
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(seed);
        }
    }

    /// <summary>
    /// Decapsulates against the private key derived from a 64-byte FIPS 203
    /// keygen seed (<c>d || z</c>). Implicit rejection is preserved by both
    /// backends. Used by the X-Wing (algorithm-id 0x03) flow.
    /// </summary>
    public static void DecapsulateFromSeed(
        ReadOnlySpan<byte> seedDz,
        ReadOnlySpan<byte> ciphertext,
        Span<byte> sharedSecret)
    {
#if NET10_0_OR_GREATER
        if (UseNative)
        {
            using var kem = MLKem.ImportPrivateSeed(MLKemAlgorithm.MLKem768, seedDz);
            kem.Decapsulate(ciphertext, sharedSecret);
            return;
        }
#endif
        var seed = seedDz.ToArray();
        try
        {
            var priv = MLKemPrivateKeyParameters.FromSeed(MLKemParameters.ml_kem_768, seed);
            var dec = new MLKemDecapsulator(MLKemParameters.ml_kem_768);
            dec.Init(priv);
            dec.Decapsulate(ciphertext, sharedSecret);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(seed);
        }
    }

    public static void Decapsulate(
        ReadOnlySpan<byte> privateKey,
        ReadOnlySpan<byte> ciphertext,
        Span<byte> sharedSecret)
    {
#if NET10_0_OR_GREATER
        if (UseNative)
        {
            // A blob written by an earlier release is the seed form, which the
            // native importer does not accept; the seed in its first 64 bytes
            // reproduces the same key.
            using var kem = privateKey.Length == LegacySeedFormPrivateKeyLength
                ? MLKem.ImportPrivateSeed(MLKemAlgorithm.MLKem768, privateKey[..SeedLength])
                : MLKem.ImportDecapsulationKey(MLKemAlgorithm.MLKem768, privateKey);
            kem.Decapsulate(ciphertext, sharedSecret);
            return;
        }
#endif
        var privBuf = privateKey.ToArray();
        try
        {
            var priv = LoadPrivateKey(privBuf);
            var dec = new MLKemDecapsulator(MLKemParameters.ml_kem_768);
            dec.Init(priv);
            dec.Decapsulate(ciphertext, sharedSecret);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(privBuf);
        }
    }

    /// <summary>
    /// Length of the private-key blob this library wrote via BouncyCastle
    /// 2.6.x: <c>seed(64) || ek(1184) || H(ek)(32) || z(32)</c>. BouncyCastle
    /// 2.7.0 changed <c>Format.SeedAndEncoding</c> to emit the FIPS 203
    /// decapsulation key instead, which is <see cref="StandardPrivateKeyLength"/>
    /// bytes and is what the native .NET backend has always produced — so the
    /// upgrade is what finally makes the two backends agree, as this class has
    /// always claimed they do. Keys persisted by an earlier release still have
    /// to open, hence <see cref="LoadPrivateKey"/>.
    /// </summary>
    private const int LegacySeedFormPrivateKeyLength = 1312;

    /// <summary>FIPS 203 ML-KEM-768 decapsulation key length.</summary>
    private const int StandardPrivateKeyLength = 2400;

    private const int SeedLength = 64;

    /// <summary>
    /// Accepts either encoding. The legacy blob carries the seed in its first
    /// 64 bytes, and deriving from that seed reproduces the identical key pair
    /// — verified against the pinned public-key hashes in
    /// <c>NistKatTests</c>, which did not move across the BouncyCastle bump.
    /// </summary>
    private static MLKemPrivateKeyParameters LoadPrivateKey(byte[] privBuf)
    {
        if (privBuf.Length == LegacySeedFormPrivateKeyLength)
        {
            var seed = privBuf[..SeedLength];
            try
            {
                return MLKemPrivateKeyParameters.FromSeed(MLKemParameters.ml_kem_768, seed);
            }
            finally
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(seed);
            }
        }

        return MLKemPrivateKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, privBuf);
    }
}
