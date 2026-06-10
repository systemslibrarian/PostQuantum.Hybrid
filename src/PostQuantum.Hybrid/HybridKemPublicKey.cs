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
        if (Algorithm == HybridKemAlgorithm.XWing)
        {
            // IETF X-Wing order: pk_M || pk_X. Stripping the algorithm-id
            // byte yields the draft's 1216-byte encapsulation key.
            _pqPublicKey.CopyTo(result.AsSpan(1));
            _classicalPublicKey.CopyTo(result.AsSpan(1 + AlgorithmSizes.MlKem768PublicKeyBytes));
        }
        else
        {
            _classicalPublicKey.CopyTo(result.AsSpan(1));
            _pqPublicKey.CopyTo(result.AsSpan(1 + AlgorithmSizes.X25519PublicKeyBytes));
        }
        return result;
    }

    /// <summary>Serializes this public key as a PEM-encoded string.</summary>
    public string ExportPem() => PemFormatter.Encode(PemLabel, Export());

    /// <summary>
    /// Parses a hybrid KEM public key from its raw wire-format bytes.
    /// All supported algorithms share the 1217-byte total length; the
    /// algorithm-id byte determines the component order (classical-first
    /// for ids 1–2, post-quantum-first for X-Wing).
    /// </summary>
    public static HybridKemPublicKey Import(ReadOnlySpan<byte> source)
    {
        if (source.Length != AlgorithmSizes.HybridKemPublicKeyBytes)
        {
            throw new HybridKeyParseException(
                HybridFailureReason.InvalidLength,
                $"Invalid hybrid KEM public-key length: expected {AlgorithmSizes.HybridKemPublicKeyBytes}, got {source.Length}.");
        }

        var algorithm = (HybridKemAlgorithm)source[0];
        switch (algorithm)
        {
            case HybridKemAlgorithm.X25519MlKem768:
            case HybridKemAlgorithm.X25519MlKem768XWing:
            {
                var classical = source.Slice(1, AlgorithmSizes.X25519PublicKeyBytes).ToArray();
                var pq = source.Slice(1 + AlgorithmSizes.X25519PublicKeyBytes, AlgorithmSizes.MlKem768PublicKeyBytes).ToArray();
                return new HybridKemPublicKey(algorithm, classical, pq);
            }
            case HybridKemAlgorithm.XWing:
            {
                var pq = source.Slice(1, AlgorithmSizes.MlKem768PublicKeyBytes).ToArray();
                var classical = source.Slice(1 + AlgorithmSizes.MlKem768PublicKeyBytes, AlgorithmSizes.X25519PublicKeyBytes).ToArray();
                return new HybridKemPublicKey(algorithm, classical, pq);
            }
            default:
                throw new HybridKeyParseException(
                    HybridFailureReason.UnsupportedAlgorithmId,
                    $"Unsupported hybrid KEM algorithm id: {source[0]}.");
        }
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

    /// <summary>
    /// Encodes this key as a standard X.509 <c>SubjectPublicKeyInfo</c>
    /// DER structure. **Preview**: the algorithm OID is a placeholder
    /// taken from RFC 5612's IANA Example PEN and will be replaced when
    /// the IETF LAMPS composite-KEM draft assigns final OIDs. See
    /// <see href="../docs/adr/0014-spki-pkcs8-preview.md">ADR 0014</see>.
    /// </summary>
    public byte[] ExportSubjectPublicKeyInfo()
    {
        if (Algorithm == HybridKemAlgorithm.XWing)
        {
            // Real id-XWing OID; per the draft's ASN.1 module the BIT STRING
            // is the raw 1216-byte pk_M || pk_X with no inner wrapping —
            // directly consumable by other X-Wing stacks.
            var raw = new byte[AlgorithmSizes.XWingPublicKeyBytes];
            _pqPublicKey.CopyTo(raw.AsSpan());
            _classicalPublicKey.CopyTo(raw.AsSpan(AlgorithmSizes.MlKem768PublicKeyBytes));
            return Pkcs8SpkiCodec.EncodeSpki(Pkcs8SpkiCodec.OidXWing, raw);
        }
        var oid = Algorithm switch
        {
            HybridKemAlgorithm.X25519MlKem768      => Pkcs8SpkiCodec.OidHybridKemHkdf,
            HybridKemAlgorithm.X25519MlKem768XWing => Pkcs8SpkiCodec.OidHybridKemXWing,
            _ => throw new PostQuantumHybridException(HybridFailureReason.UnsupportedAlgorithmId, $"Unsupported hybrid KEM algorithm: {Algorithm}"),
        };
        return Pkcs8SpkiCodec.EncodeSpki(oid, Export());
    }

    /// <summary>
    /// Decodes a SubjectPublicKeyInfo (DER) produced by
    /// <see cref="ExportSubjectPublicKeyInfo"/>. **Preview** — placeholder OIDs.
    /// </summary>
    public static HybridKemPublicKey ImportSubjectPublicKeyInfo(ReadOnlySpan<byte> spkiDer)
    {
        var (oid, keyBytes) = Pkcs8SpkiCodec.DecodeSpki(spkiDer);
        if (oid == Pkcs8SpkiCodec.OidXWing)
        {
            if (keyBytes.Length != AlgorithmSizes.XWingPublicKeyBytes)
            {
                throw new HybridKeyParseException(
                    HybridFailureReason.InvalidLength,
                    $"Invalid X-Wing SubjectPublicKeyInfo key length: expected {AlgorithmSizes.XWingPublicKeyBytes}, got {keyBytes.Length}.");
            }
            var pq = keyBytes.AsSpan(0, AlgorithmSizes.MlKem768PublicKeyBytes).ToArray();
            var classical = keyBytes.AsSpan(AlgorithmSizes.MlKem768PublicKeyBytes).ToArray();
            return new HybridKemPublicKey(HybridKemAlgorithm.XWing, classical, pq);
        }
        if (oid != Pkcs8SpkiCodec.OidHybridKemHkdf && oid != Pkcs8SpkiCodec.OidHybridKemXWing)
        {
            throw new HybridKeyParseException(
                HybridFailureReason.UnsupportedAlgorithmId,
                $"SubjectPublicKeyInfo OID {oid} is not a recognised PostQuantum.Hybrid hybrid-KEM OID.");
        }
        return Import(keyBytes);
    }
}
