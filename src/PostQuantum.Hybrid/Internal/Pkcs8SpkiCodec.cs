using System.Formats.Asn1;

namespace PostQuantum.Hybrid.Internal;

/// <summary>
/// ASN.1 encoder/decoder for wrapping PostQuantum.Hybrid wire-format
/// blobs in standard <c>SubjectPublicKeyInfo</c> (X.509 SPKI) and
/// <c>PrivateKeyInfo</c> (PKCS#8) envelopes. Used by the
/// <c>ExportSubjectPublicKeyInfo</c> / <c>ImportSubjectPublicKeyInfo</c> /
/// <c>ExportPkcs8PrivateKey</c> / <c>ImportPkcs8PrivateKey</c> methods
/// on the public-facing key types.
/// </summary>
/// <remarks>
/// <para><b>Preview — placeholder OIDs.</b> The IETF LAMPS WG's
/// composite-KEM / composite-signature drafts have not finalized
/// algorithm OIDs at the time of v1.x. The OIDs encoded here live
/// under the IANA Example PEN <c>1.3.6.1.4.1.32473</c> (RFC 5612) and
/// are NOT intended for cross-implementation interop. They exist so
/// callers that need to embed a PostQuantum.Hybrid key inside an X.509
/// certificate template or a key store that expects ASN.1 framing have
/// a structurally valid blob to work with. The OIDs will be replaced
/// with the IETF-allocated values when LAMPS publishes them; that will
/// be a wire-format-breaking change announced via a new
/// <see cref="HybridKemAlgorithm"/> / <see cref="HybridSignatureAlgorithm"/>
/// value and a new ADR.</para>
/// <para>For lossless round-tripping inside the PostQuantum.Hybrid
/// ecosystem, the inner key bytes are the existing wire format
/// (algorithm-id byte || classical || pq). Decoding therefore only
/// requires reading the OCTET STRING / BIT STRING contents and feeding
/// them to the existing <c>Import</c> path.</para>
/// </remarks>
internal static class Pkcs8SpkiCodec
{
    /// <summary>Hybrid KEM X25519+ML-KEM-768 (HKDF-SHA256 combiner) — placeholder.</summary>
    public const string OidHybridKemHkdf   = "1.3.6.1.4.1.32473.1.1.1";

    /// <summary>Hybrid KEM X25519+ML-KEM-768 (X-Wing combiner) — placeholder.</summary>
    public const string OidHybridKemXWing  = "1.3.6.1.4.1.32473.1.1.2";

    /// <summary>Hybrid signature Ed25519+ML-DSA-65 — placeholder.</summary>
    public const string OidHybridSig       = "1.3.6.1.4.1.32473.1.2.1";

    /// <summary>
    /// <c>id-XWing</c> from the X-Wing draft's ASN.1 module
    /// (X509-XWING-2024) — a REAL allocated OID, not a placeholder. Used
    /// for <see cref="HybridKemAlgorithm.XWing"/> (algorithm-id 0x03).
    /// Per the draft there is no inner ASN.1 wrapping: the SPKI BIT STRING
    /// is the raw 1216-byte encapsulation key and the PKCS#8 OCTET STRING
    /// is the raw 32-byte seed (no PostQuantum.Hybrid algorithm-id prefix),
    /// so the envelopes interoperate with other X-Wing implementations.
    /// </summary>
    public const string OidXWing           = "1.3.6.1.4.1.62253.25722";

    /// <summary>
    /// Encodes a SubjectPublicKeyInfo around <paramref name="rawWireFormat"/>.
    /// </summary>
    public static byte[] EncodeSpki(string algorithmOid, ReadOnlySpan<byte> rawWireFormat)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            // AlgorithmIdentifier
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier(algorithmOid);
                // No parameters — hybrid construction is self-describing.
            }
            // subjectPublicKey BIT STRING (0 unused bits)
            w.WriteBitString(rawWireFormat);
        }
        return w.Encode();
    }

    /// <summary>
    /// Decodes a SubjectPublicKeyInfo, returning the algorithm OID and
    /// the inner key bytes. Throws <see cref="AsnContentException"/> on
    /// malformed input.
    /// </summary>
    public static (string Oid, byte[] KeyBytes) DecodeSpki(ReadOnlySpan<byte> spkiDer)
    {
        var reader = new AsnReader(spkiDer.ToArray(), AsnEncodingRules.DER);
        var spki = reader.ReadSequence();
        reader.ThrowIfNotEmpty();

        var algId = spki.ReadSequence();
        var oid = algId.ReadObjectIdentifier();
        // Skip any parameters.
        while (algId.HasData) { algId.ReadEncodedValue(); }

        var keyBytes = spki.ReadBitString(out var unusedBitCount);
        if (unusedBitCount != 0)
        {
            throw new AsnContentException("SubjectPublicKeyInfo: unusedBitCount must be 0 for byte-aligned hybrid keys.");
        }
        spki.ThrowIfNotEmpty();
        return (oid, keyBytes);
    }

    /// <summary>
    /// Encodes a PrivateKeyInfo (PKCS#8 v1) around the raw wire format.
    /// </summary>
    public static byte[] EncodePkcs8(string algorithmOid, ReadOnlySpan<byte> rawWireFormat)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            // version
            w.WriteInteger(0);
            // privateKeyAlgorithm
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier(algorithmOid);
            }
            // privateKey OCTET STRING — wraps the raw wire format. PKCS#8
            // requires the OCTET STRING to wrap an algorithm-specific
            // encoding, which here is our concatenated hybrid blob.
            w.WriteOctetString(rawWireFormat);
        }
        return w.Encode();
    }

    /// <summary>
    /// Decodes a PrivateKeyInfo, returning the algorithm OID and the
    /// inner key bytes. The transient DER copy taken for the
    /// <see cref="AsnReader"/> (PKCS#8 carries private key material) is
    /// zeroed before returning.
    /// </summary>
    public static (string Oid, byte[] KeyBytes) DecodePkcs8(ReadOnlySpan<byte> pkcs8Der)
    {
        var pkcs8Buf = pkcs8Der.ToArray();
        try
        {
            var reader = new AsnReader(pkcs8Buf, AsnEncodingRules.DER);
            var info = reader.ReadSequence();
            reader.ThrowIfNotEmpty();

            var version = info.ReadInteger();
            if (version != System.Numerics.BigInteger.Zero)
            {
                throw new AsnContentException($"PrivateKeyInfo: unsupported version {version}.");
            }

            var algId = info.ReadSequence();
            var oid = algId.ReadObjectIdentifier();
            while (algId.HasData) { algId.ReadEncodedValue(); }

            var keyBytes = info.ReadOctetString();
            // Optional attributes: ignore.
            while (info.HasData) { info.ReadEncodedValue(); }
            return (oid, keyBytes);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(pkcs8Buf);
        }
    }
}
