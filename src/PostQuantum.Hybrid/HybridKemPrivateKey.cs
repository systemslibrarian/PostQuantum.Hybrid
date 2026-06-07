using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
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
            throw new HybridKeyParseException(
                HybridFailureReason.InvalidLength,
                $"Invalid hybrid KEM private-key length: expected {AlgorithmSizes.HybridKemPrivateKeyBytes}, got {source.Length}.");
        }

        var algorithm = (HybridKemAlgorithm)source[0];
        if (algorithm != HybridKemAlgorithm.X25519MlKem768 &&
            algorithm != HybridKemAlgorithm.X25519MlKem768XWing)
        {
            throw new HybridKeyParseException(
                HybridFailureReason.UnsupportedAlgorithmId,
                $"Unsupported hybrid KEM algorithm id: {source[0]}.");
        }

        var classical = source.Slice(1, AlgorithmSizes.X25519PrivateKeyBytes).ToArray();
        var pq = source.Slice(1 + AlgorithmSizes.X25519PrivateKeyBytes, AlgorithmSizes.MlKem768PrivateKeyBytes).ToArray();
        return new HybridKemPrivateKey(algorithm, classical, pq);
    }

    /// <summary>Parses a hybrid KEM private key from PEM.</summary>
    public static HybridKemPrivateKey ImportPem(string pem)
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
    /// Non-throwing counterpart to <see cref="Import"/>. On failure
    /// <paramref name="key"/> is <see langword="null"/>; on success the
    /// caller owns the returned instance and must dispose it.
    /// </summary>
    public static bool TryImport(ReadOnlySpan<byte> source, [NotNullWhen(true)] out HybridKemPrivateKey? key)
    {
        try { key = Import(source); return true; }
        catch (Exception ex) when (ex is PostQuantumHybridException or CryptographicException or FormatException)
        { key = null; return false; }
    }

    /// <summary>
    /// Non-throwing counterpart to <see cref="ImportPem"/>. On failure
    /// <paramref name="key"/> is <see langword="null"/>; on success the
    /// caller owns the returned instance and must dispose it.
    /// </summary>
    public static bool TryImportPem(string pem, [NotNullWhen(true)] out HybridKemPrivateKey? key)
    {
        try { key = ImportPem(pem); return true; }
        catch (Exception ex) when (ex is PostQuantumHybridException or CryptographicException or FormatException or ArgumentNullException)
        { key = null; return false; }
    }

    /// <summary>
    /// Encodes this key as a PKCS#8 <c>PrivateKeyInfo</c> DER structure.
    /// **Preview**: the algorithm OID is a placeholder taken from
    /// RFC 5612's IANA Example PEN and will be replaced when the IETF
    /// LAMPS composite-KEM draft assigns final OIDs. See
    /// <see href="../docs/adr/0014-spki-pkcs8-preview.md">ADR 0014</see>.
    /// The returned buffer holds sensitive material — zero it after use.
    /// </summary>
    public byte[] ExportPkcs8PrivateKey()
    {
        ThrowIfDisposed();
        var oid = Algorithm switch
        {
            HybridKemAlgorithm.X25519MlKem768      => Pkcs8SpkiCodec.OidHybridKemHkdf,
            HybridKemAlgorithm.X25519MlKem768XWing => Pkcs8SpkiCodec.OidHybridKemXWing,
            _ => throw new PostQuantumHybridException(HybridFailureReason.UnsupportedAlgorithmId, $"Unsupported hybrid KEM algorithm: {Algorithm}"),
        };
        var raw = Export();
        try
        {
            return Pkcs8SpkiCodec.EncodePkcs8(oid, raw);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(raw);
        }
    }

    /// <summary>
    /// Decodes a PKCS#8 PrivateKeyInfo (DER) produced by
    /// <see cref="ExportPkcs8PrivateKey"/>. The caller owns the returned
    /// instance and must dispose it. **Preview** — placeholder OIDs.
    /// </summary>
    public static HybridKemPrivateKey ImportPkcs8PrivateKey(ReadOnlySpan<byte> pkcs8Der)
    {
        var (oid, keyBytes) = Pkcs8SpkiCodec.DecodePkcs8(pkcs8Der);
        try
        {
            if (oid != Pkcs8SpkiCodec.OidHybridKemHkdf && oid != Pkcs8SpkiCodec.OidHybridKemXWing)
            {
                throw new HybridKeyParseException(
                    HybridFailureReason.UnsupportedAlgorithmId,
                    $"PrivateKeyInfo OID {oid} is not a recognised PostQuantum.Hybrid hybrid-KEM OID.");
            }
            return Import(keyBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
        }
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
            throw new ObjectDisposedException(nameof(HybridKemPrivateKey));
        }
    }
}
