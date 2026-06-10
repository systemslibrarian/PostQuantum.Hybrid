using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using PostQuantum.Hybrid.Internal;

namespace PostQuantum.Hybrid;

/// <summary>
/// A hybrid KEM ciphertext produced by <see cref="HybridKem.Encapsulate"/>.
/// Send this to the holder of the matching <see cref="HybridKemPrivateKey"/>.
/// </summary>
[DebuggerDisplay("HybridKemCiphertext {Algorithm} ({ToBytes().Length} bytes)")]
public sealed class HybridKemCiphertext
{
    private readonly byte[] _classicalCiphertext;
    private readonly byte[] _pqCiphertext;

    /// <summary>The algorithm combination this ciphertext belongs to.</summary>
    public HybridKemAlgorithm Algorithm { get; }

    internal HybridKemCiphertext(
        HybridKemAlgorithm algorithm,
        byte[] classicalCiphertext,
        byte[] pqCiphertext)
    {
        Algorithm = algorithm;
        _classicalCiphertext = classicalCiphertext;
        _pqCiphertext = pqCiphertext;
    }

    internal ReadOnlySpan<byte> ClassicalSpan => _classicalCiphertext;
    internal ReadOnlySpan<byte> PqSpan => _pqCiphertext;

    /// <summary>Serializes this ciphertext to its raw wire-format byte representation.</summary>
    public byte[] ToBytes()
    {
        var result = new byte[AlgorithmSizes.HybridKemCiphertextBytes];
        result[0] = (byte)Algorithm;
        if (Algorithm == HybridKemAlgorithm.XWing)
        {
            // IETF X-Wing order: ct_M || ct_X. Stripping the algorithm-id
            // byte yields the draft's 1120-byte ciphertext.
            _pqCiphertext.CopyTo(result.AsSpan(1));
            _classicalCiphertext.CopyTo(result.AsSpan(1 + AlgorithmSizes.MlKem768CiphertextBytes));
        }
        else
        {
            _classicalCiphertext.CopyTo(result.AsSpan(1));
            _pqCiphertext.CopyTo(result.AsSpan(1 + AlgorithmSizes.X25519PublicKeyBytes));
        }
        return result;
    }

    /// <summary>Parses a hybrid KEM ciphertext from its raw wire-format bytes.</summary>
    public static HybridKemCiphertext FromBytes(ReadOnlySpan<byte> source)
    {
        if (source.Length != AlgorithmSizes.HybridKemCiphertextBytes)
        {
            throw new InvalidCiphertextException(
                HybridFailureReason.InvalidLength,
                $"Invalid hybrid KEM ciphertext length: expected {AlgorithmSizes.HybridKemCiphertextBytes}, got {source.Length}.");
        }

        var algorithm = (HybridKemAlgorithm)source[0];
        switch (algorithm)
        {
            case HybridKemAlgorithm.X25519MlKem768:
            case HybridKemAlgorithm.X25519MlKem768XWing:
            {
                var classical = source.Slice(1, AlgorithmSizes.X25519PublicKeyBytes).ToArray();
                var pq = source.Slice(1 + AlgorithmSizes.X25519PublicKeyBytes, AlgorithmSizes.MlKem768CiphertextBytes).ToArray();
                return new HybridKemCiphertext(algorithm, classical, pq);
            }
            case HybridKemAlgorithm.XWing:
            {
                var pq = source.Slice(1, AlgorithmSizes.MlKem768CiphertextBytes).ToArray();
                var classical = source.Slice(1 + AlgorithmSizes.MlKem768CiphertextBytes, AlgorithmSizes.X25519PublicKeyBytes).ToArray();
                return new HybridKemCiphertext(algorithm, classical, pq);
            }
            default:
                throw new InvalidCiphertextException(
                    HybridFailureReason.UnsupportedAlgorithmId,
                    $"Unsupported hybrid KEM algorithm id: {source[0]}.");
        }
    }

    /// <summary>Non-throwing counterpart to <see cref="FromBytes"/>.</summary>
    public static bool TryFromBytes(ReadOnlySpan<byte> source, [NotNullWhen(true)] out HybridKemCiphertext? ciphertext)
    {
        try { ciphertext = FromBytes(source); return true; }
        catch (Exception ex) when (ex is PostQuantumHybridException or CryptographicException or FormatException)
        { ciphertext = null; return false; }
    }
}
