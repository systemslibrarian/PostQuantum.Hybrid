using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using PostQuantum.Hybrid.Internal;

namespace PostQuantum.Hybrid;

/// <summary>
/// A hybrid signature verification (public) key combining a classical key
/// with a post-quantum key in a single wire-format blob.
/// </summary>
[DebuggerDisplay("HybridSignaturePublicKey {Algorithm} ({Export().Length} bytes)")]
public sealed class HybridSignaturePublicKey
{
    internal const string PemLabel = "PQH HYBRID SIG PUBLIC KEY";

    private readonly byte[] _classicalPublicKey;
    private readonly byte[] _pqPublicKey;

    /// <summary>The algorithm combination this key belongs to.</summary>
    public HybridSignatureAlgorithm Algorithm { get; }

    internal HybridSignaturePublicKey(
        HybridSignatureAlgorithm algorithm,
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
        var result = new byte[AlgorithmSizes.HybridSigPublicKeyBytes];
        result[0] = (byte)Algorithm;
        _classicalPublicKey.CopyTo(result.AsSpan(1));
        _pqPublicKey.CopyTo(result.AsSpan(1 + AlgorithmSizes.Ed25519PublicKeyBytes));
        return result;
    }

    /// <summary>Serializes this public key as a PEM-encoded string.</summary>
    public string ExportPem() => PemFormatter.Encode(PemLabel, Export());

    /// <summary>Parses a hybrid signature public key from its raw wire-format bytes.</summary>
    public static HybridSignaturePublicKey Import(ReadOnlySpan<byte> source)
    {
        if (source.Length != AlgorithmSizes.HybridSigPublicKeyBytes)
        {
            throw new HybridKeyParseException(
                HybridFailureReason.InvalidLength,
                $"Invalid hybrid signature public-key length: expected {AlgorithmSizes.HybridSigPublicKeyBytes}, got {source.Length}.");
        }

        var algorithm = (HybridSignatureAlgorithm)source[0];
        if (algorithm != HybridSignatureAlgorithm.Ed25519MlDsa65)
        {
            throw new HybridKeyParseException(
                HybridFailureReason.UnsupportedAlgorithmId,
                $"Unsupported hybrid signature algorithm id: {source[0]}.");
        }

        var classical = source.Slice(1, AlgorithmSizes.Ed25519PublicKeyBytes).ToArray();
        var pq = source.Slice(1 + AlgorithmSizes.Ed25519PublicKeyBytes, AlgorithmSizes.MlDsa65PublicKeyBytes).ToArray();
        return new HybridSignaturePublicKey(algorithm, classical, pq);
    }

    /// <summary>Parses a hybrid signature public key from PEM.</summary>
    public static HybridSignaturePublicKey ImportPem(string pem) => Import(PemFormatter.Decode(pem, PemLabel));

    /// <summary>Non-throwing counterpart to <see cref="Import"/>.</summary>
    public static bool TryImport(ReadOnlySpan<byte> source, [NotNullWhen(true)] out HybridSignaturePublicKey? key)
    {
        try { key = Import(source); return true; }
        catch (Exception ex) when (ex is PostQuantumHybridException or CryptographicException or FormatException)
        { key = null; return false; }
    }

    /// <summary>Non-throwing counterpart to <see cref="ImportPem"/>.</summary>
    public static bool TryImportPem(string pem, [NotNullWhen(true)] out HybridSignaturePublicKey? key)
    {
        try { key = ImportPem(pem); return true; }
        catch (Exception ex) when (ex is PostQuantumHybridException or CryptographicException or FormatException or ArgumentNullException)
        { key = null; return false; }
    }
}
