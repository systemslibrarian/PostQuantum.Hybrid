using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using PostQuantum.Hybrid.Internal;

namespace PostQuantum.Hybrid;

/// <summary>
/// A hybrid KEM public key (recipient-side encapsulation key).
/// Combines a classical key with a post-quantum key in a single wire-format blob.
/// </summary>
[DebuggerDisplay("HybridKemPublicKey {Algorithm} ({Export().Length} bytes)")]
public sealed class HybridKemPublicKey
{
    internal const string PemLabel = "PQH HYBRID KEM PUBLIC KEY";

    private readonly byte[] _classicalPublicKey;
    private readonly byte[] _pqPublicKey;

    /// <summary>The algorithm combination this key belongs to.</summary>
    public HybridKemAlgorithm Algorithm { get; }

    internal HybridKemPublicKey(
        HybridKemAlgorithm algorithm,
        byte[] classicalPublicKey,
        byte[] pqPublicKey)
    {
        Algorithm = algorithm;
        _classicalPublicKey = classicalPublicKey;
        _pqPublicKey = pqPublicKey;
    }

    internal ReadOnlySpan<byte> ClassicalKeySpan => _classicalPublicKey;
    internal ReadOnlySpan<byte> PqKeySpan => _pqPublicKey;

    /// <summary>Serializes this public key to its raw wire-format byte representation.</summary>
    public byte[] Export()
    {
        var result = new byte[AlgorithmSizes.HybridKemPublicKeyBytes];
        result[0] = (byte)Algorithm;
        _classicalPublicKey.CopyTo(result.AsSpan(1));
        _pqPublicKey.CopyTo(result.AsSpan(1 + AlgorithmSizes.X25519PublicKeyBytes));
        return result;
    }

    /// <summary>Serializes this public key as a PEM-encoded string.</summary>
    public string ExportPem() => PemFormatter.Encode(PemLabel, Export());

    /// <summary>Parses a hybrid KEM public key from its raw wire-format bytes.</summary>
    public static HybridKemPublicKey Import(ReadOnlySpan<byte> source)
    {
        if (source.Length != AlgorithmSizes.HybridKemPublicKeyBytes)
        {
            throw new HybridKeyParseException(
                HybridFailureReason.InvalidLength,
                $"Invalid hybrid KEM public-key length: expected {AlgorithmSizes.HybridKemPublicKeyBytes}, got {source.Length}.");
        }

        var algorithm = (HybridKemAlgorithm)source[0];
        if (algorithm != HybridKemAlgorithm.X25519MlKem768 &&
            algorithm != HybridKemAlgorithm.X25519MlKem768XWing)
        {
            throw new HybridKeyParseException(
                HybridFailureReason.UnsupportedAlgorithmId,
                $"Unsupported hybrid KEM algorithm id: {source[0]}.");
        }

        var classical = source.Slice(1, AlgorithmSizes.X25519PublicKeyBytes).ToArray();
        var pq = source.Slice(1 + AlgorithmSizes.X25519PublicKeyBytes, AlgorithmSizes.MlKem768PublicKeyBytes).ToArray();
        return new HybridKemPublicKey(algorithm, classical, pq);
    }

    /// <summary>Parses a hybrid KEM public key from PEM.</summary>
    public static HybridKemPublicKey ImportPem(string pem) => Import(PemFormatter.Decode(pem, PemLabel));

    /// <summary>
    /// Non-throwing counterpart to <see cref="Import"/>. Returns
    /// <see langword="true"/> and the parsed key on success; returns
    /// <see langword="false"/> with <paramref name="key"/> set to
    /// <see langword="null"/> on any parse failure.
    /// </summary>
    public static bool TryImport(ReadOnlySpan<byte> source, [NotNullWhen(true)] out HybridKemPublicKey? key)
    {
        try { key = Import(source); return true; }
        catch (Exception ex) when (ex is PostQuantumHybridException or CryptographicException or FormatException)
        { key = null; return false; }
    }

    /// <summary>
    /// Non-throwing counterpart to <see cref="ImportPem"/>. Returns
    /// <see langword="true"/> and the parsed key on success; returns
    /// <see langword="false"/> with <paramref name="key"/> set to
    /// <see langword="null"/> on any PEM-decode or parse failure.
    /// </summary>
    public static bool TryImportPem(string pem, [NotNullWhen(true)] out HybridKemPublicKey? key)
    {
        try { key = ImportPem(pem); return true; }
        catch (Exception ex) when (ex is PostQuantumHybridException or CryptographicException or FormatException or ArgumentNullException)
        { key = null; return false; }
    }
}
