using System.Diagnostics;
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
        _classicalCiphertext.CopyTo(result.AsSpan(1));
        _pqCiphertext.CopyTo(result.AsSpan(1 + AlgorithmSizes.X25519PublicKeyBytes));
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
        if (algorithm != HybridKemAlgorithm.X25519MlKem768)
        {
            throw new InvalidCiphertextException(
                HybridFailureReason.UnsupportedAlgorithmId,
                $"Unsupported hybrid KEM algorithm id: {source[0]}.");
        }

        var classical = source.Slice(1, AlgorithmSizes.X25519PublicKeyBytes).ToArray();
        var pq = source.Slice(1 + AlgorithmSizes.X25519PublicKeyBytes, AlgorithmSizes.MlKem768CiphertextBytes).ToArray();
        return new HybridKemCiphertext(algorithm, classical, pq);
    }
}
