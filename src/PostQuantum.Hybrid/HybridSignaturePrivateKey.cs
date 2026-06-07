using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using PostQuantum.Hybrid.Internal;

namespace PostQuantum.Hybrid;

/// <summary>
/// A hybrid signature signing (private) key. Must be disposed to clear
/// sensitive material.
/// </summary>
[DebuggerDisplay("HybridSignaturePrivateKey {Algorithm} (REDACTED)")]
public sealed class HybridSignaturePrivateKey : IDisposable
{
    internal const string PemLabel = "PQH HYBRID SIG PRIVATE KEY";

    private byte[] _classicalPrivateKey;
    private byte[] _pqPrivateKey;
    private bool _disposed;

    /// <summary>The algorithm combination this key belongs to.</summary>
    public HybridSignatureAlgorithm Algorithm { get; }

    internal HybridSignaturePrivateKey(
        HybridSignatureAlgorithm algorithm,
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
        var result = new byte[AlgorithmSizes.HybridSigPrivateKeyBytes];
        result[0] = (byte)Algorithm;
        _classicalPrivateKey.CopyTo(result.AsSpan(1));
        _pqPrivateKey.CopyTo(result.AsSpan(1 + AlgorithmSizes.Ed25519PrivateKeyBytes));
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

    /// <summary>Parses a hybrid signature private key from its raw wire-format bytes.</summary>
    public static HybridSignaturePrivateKey Import(ReadOnlySpan<byte> source)
    {
        if (source.Length != AlgorithmSizes.HybridSigPrivateKeyBytes)
        {
            throw new HybridKeyParseException(
                HybridFailureReason.InvalidLength,
                $"Invalid hybrid signature private-key length: expected {AlgorithmSizes.HybridSigPrivateKeyBytes}, got {source.Length}.");
        }

        var algorithm = (HybridSignatureAlgorithm)source[0];
        if (algorithm != HybridSignatureAlgorithm.Ed25519MlDsa65)
        {
            throw new HybridKeyParseException(
                HybridFailureReason.UnsupportedAlgorithmId,
                $"Unsupported hybrid signature algorithm id: {source[0]}.");
        }

        var classical = source.Slice(1, AlgorithmSizes.Ed25519PrivateKeyBytes).ToArray();
        var pq = source.Slice(1 + AlgorithmSizes.Ed25519PrivateKeyBytes, AlgorithmSizes.MlDsa65PrivateKeyBytes).ToArray();
        return new HybridSignaturePrivateKey(algorithm, classical, pq);
    }

    /// <summary>Parses a hybrid signature private key from PEM.</summary>
    public static HybridSignaturePrivateKey ImportPem(string pem)
    {
        var decoded = PemFormatter.Decode(pem, PemLabel);
        try
        {
            return Import(decoded);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(decoded);
        }
    }

    /// <summary>
    /// Non-throwing counterpart to <see cref="Import"/>. On success the
    /// caller owns the returned instance and must dispose it.
    /// </summary>
    public static bool TryImport(ReadOnlySpan<byte> source, [NotNullWhen(true)] out HybridSignaturePrivateKey? key)
    {
        try { key = Import(source); return true; }
        catch (Exception ex) when (ex is PostQuantumHybridException or CryptographicException or FormatException)
        { key = null; return false; }
    }

    /// <summary>
    /// Non-throwing counterpart to <see cref="ImportPem"/>. On success the
    /// caller owns the returned instance and must dispose it.
    /// </summary>
    public static bool TryImportPem(string pem, [NotNullWhen(true)] out HybridSignaturePrivateKey? key)
    {
        try { key = ImportPem(pem); return true; }
        catch (Exception ex) when (ex is PostQuantumHybridException or CryptographicException or FormatException or ArgumentNullException)
        { key = null; return false; }
    }

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
            throw new ObjectDisposedException(nameof(HybridSignaturePrivateKey));
        }
    }
}
