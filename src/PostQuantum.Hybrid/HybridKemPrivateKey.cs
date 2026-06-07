using System.Diagnostics;
using System.Security.Cryptography;
using PostQuantum.Hybrid.Internal;

namespace PostQuantum.Hybrid;

/// <summary>
/// A hybrid KEM private key (recipient-side decapsulation key).
/// Must be disposed to clear sensitive material.
/// </summary>
[DebuggerDisplay("HybridKemPrivateKey {Algorithm} (REDACTED)")]
public sealed class HybridKemPrivateKey : IDisposable
{
    internal const string PemLabel = "PQH HYBRID KEM PRIVATE KEY";

    private byte[] _classicalPrivateKey;
    private byte[] _pqPrivateKey;
    private bool _disposed;

    /// <summary>The algorithm combination this key belongs to.</summary>
    public HybridKemAlgorithm Algorithm { get; }

    internal HybridKemPrivateKey(
        HybridKemAlgorithm algorithm,
        byte[] classicalPrivateKey,
        byte[] pqPrivateKey)
    {
        Algorithm = algorithm;
        _classicalPrivateKey = classicalPrivateKey;
        _pqPrivateKey = pqPrivateKey;
    }

    internal ReadOnlySpan<byte> ClassicalKeySpan
    {
        get { ThrowIfDisposed(); return _classicalPrivateKey; }
    }

    internal ReadOnlySpan<byte> PqKeySpan
    {
        get { ThrowIfDisposed(); return _pqPrivateKey; }
    }

    /// <summary>
    /// Serializes this private key to its raw wire-format byte representation.
    /// The returned buffer contains sensitive material; clear it after use.
    /// </summary>
    public byte[] Export()
    {
        ThrowIfDisposed();
        var result = new byte[AlgorithmSizes.HybridKemPrivateKeyBytes];
        result[0] = (byte)Algorithm;
        _classicalPrivateKey.CopyTo(result.AsSpan(1));
        _pqPrivateKey.CopyTo(result.AsSpan(1 + AlgorithmSizes.X25519PrivateKeyBytes));
        return result;
    }

    /// <summary>Serializes this private key as a PEM-encoded string.</summary>
    public string ExportPem()
    {
        var bytes = Export();
        try
        {
            return PemFormatter.Encode(PemLabel, bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <summary>Parses a hybrid KEM private key from its raw wire-format bytes.</summary>
    public static HybridKemPrivateKey Import(ReadOnlySpan<byte> source)
    {
        if (source.Length != AlgorithmSizes.HybridKemPrivateKeyBytes)
        {
            throw new PostQuantumHybridException(
                HybridFailureReason.InvalidLength,
                $"Invalid hybrid KEM private-key length: expected {AlgorithmSizes.HybridKemPrivateKeyBytes}, got {source.Length}.");
        }

        var algorithm = (HybridKemAlgorithm)source[0];
        if (algorithm != HybridKemAlgorithm.X25519MlKem768)
        {
            throw new PostQuantumHybridException(
                HybridFailureReason.UnsupportedAlgorithmId,
                $"Unsupported hybrid KEM algorithm id: {source[0]}.");
        }

        var classical = source.Slice(1, AlgorithmSizes.X25519PrivateKeyBytes).ToArray();
        var pq = source.Slice(1 + AlgorithmSizes.X25519PrivateKeyBytes, AlgorithmSizes.MlKem768PrivateKeyBytes).ToArray();
        return new HybridKemPrivateKey(algorithm, classical, pq);
    }

    /// <summary>Parses a hybrid KEM private key from PEM.</summary>
    public static HybridKemPrivateKey ImportPem(string pem) => Import(PemFormatter.Decode(pem, PemLabel));

    /// <summary>Clears the sensitive key material held by this instance.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        CryptographicOperations.ZeroMemory(_classicalPrivateKey);
        CryptographicOperations.ZeroMemory(_pqPrivateKey);
        _classicalPrivateKey = Array.Empty<byte>();
        _pqPrivateKey = Array.Empty<byte>();
        _disposed = true;
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(HybridKemPrivateKey));
        }
    }
}
