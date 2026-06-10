using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Text.Json;
using Xunit;

namespace PostQuantum.Hybrid.Tests;

/// <summary>
/// Strict IETF X-Wing conformance tests for algorithm-id 0x03
/// (<see cref="HybridKemAlgorithm.XWing"/>, ADR 0015), validated against
/// the official artifacts vendored from the draft repository at tag
/// draft-connolly-cfrg-xwing-kem-10 (see <c>fixtures/xwing/NOTICE.md</c>):
/// the draft's KAT vectors (<c>test-vectors.json</c>) and the
/// CIRCL-generated SPKI / PKCS#8 fixtures (<c>xwing.pub</c> /
/// <c>xwing.priv</c>).
/// </summary>
public class XWingIetfInteropTests
{
    private static string FixturePath(string name) =>
        Path.Combine(AppContext.BaseDirectory, "fixtures", "xwing", name);

    private sealed record Vector(byte[] Seed, byte[] Sk, byte[] Pk, byte[] Ct, byte[] Ss);

    private static List<Vector> LoadVectors()
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(FixturePath("test-vectors.json")));
        var vectors = new List<Vector>();
        foreach (var v in doc.RootElement.EnumerateArray())
        {
            vectors.Add(new Vector(
                Convert.FromHexString(v.GetProperty("seed").GetString()!),
                Convert.FromHexString(v.GetProperty("sk").GetString()!),
                Convert.FromHexString(v.GetProperty("pk").GetString()!),
                Convert.FromHexString(v.GetProperty("ct").GetString()!),
                Convert.FromHexString(v.GetProperty("ss").GetString()!)));
        }
        Assert.Equal(3, vectors.Count);
        return vectors;
    }

    /// <summary>Prepends the 0x03 algorithm-id byte to raw IETF X-Wing bytes.</summary>
    private static byte[] WithAlgId(byte[] ietfBytes)
    {
        var result = new byte[ietfBytes.Length + 1];
        result[0] = 0x03;
        ietfBytes.CopyTo(result, 1);
        return result;
    }

    private static byte[] ReadPemDer(string fixtureName)
    {
        var pem = File.ReadAllText(FixturePath(fixtureName));
        var fields = PemEncoding.Find(pem);
        return Convert.FromBase64String(pem[fields.Base64Data]);
    }

    // ---- Official KAT vectors ------------------------------------------

    [Fact]
    public void OfficialVectors_Decapsulate_MatchesSharedSecret()
    {
        foreach (var v in LoadVectors())
        {
            using var priv = HybridKemPrivateKey.Import(WithAlgId(v.Sk));
            var ct = HybridKemCiphertext.FromBytes(WithAlgId(v.Ct));
            var ss = HybridKem.Decapsulate(priv, ct);
            Assert.True(CryptographicOperations.FixedTimeEquals(v.Ss, ss),
                "decapsulated secret must match the draft's official KAT shared secret");
            CryptographicOperations.ZeroMemory(ss);
        }
    }

    [Fact]
    public void OfficialVectors_SkIsTheSeed()
    {
        // The draft defines the decapsulation key AS the 32-byte seed.
        foreach (var v in LoadVectors())
        {
            Assert.Equal(v.Seed, v.Sk);
            Assert.Equal(32, v.Sk.Length);
            Assert.Equal(1216, v.Pk.Length);
            Assert.Equal(1120, v.Ct.Length);
            Assert.Equal(32, v.Ss.Length);
        }
    }

    [Fact]
    public void OfficialVectors_ImportExport_RoundTripsByteForByte()
    {
        foreach (var v in LoadVectors())
        {
            var pubWire = WithAlgId(v.Pk);
            var pub = HybridKemPublicKey.Import(pubWire);
            Assert.Equal(HybridKemAlgorithm.XWing, pub.Algorithm);
            Assert.Equal(pubWire, pub.Export());

            var privWire = WithAlgId(v.Sk);
            using var priv = HybridKemPrivateKey.Import(privWire);
            Assert.Equal(HybridKemAlgorithm.XWing, priv.Algorithm);
            Assert.Equal(privWire, priv.Export());

            var ctWire = WithAlgId(v.Ct);
            var ct = HybridKemCiphertext.FromBytes(ctWire);
            Assert.Equal(HybridKemAlgorithm.XWing, ct.Algorithm);
            Assert.Equal(ctWire, ct.ToBytes());
        }
    }

    [Fact]
    public void OfficialVectors_EncapsulateAgainstVectorPk_DecapsulatesWithVectorSk()
    {
        // Proves the vendored pk really is the encapsulation key for sk:
        // fresh encapsulation against pk must decapsulate under sk.
        foreach (var v in LoadVectors())
        {
            var pub = HybridKemPublicKey.Import(WithAlgId(v.Pk));
            using var priv = HybridKemPrivateKey.Import(WithAlgId(v.Sk));
            using var enc = HybridKem.Encapsulate(pub);
            Assert.Equal(HybridKemAlgorithm.XWing, enc.Ciphertext.Algorithm);
            var recovered = HybridKem.Decapsulate(priv, enc.Ciphertext);
            Assert.True(CryptographicOperations.FixedTimeEquals(enc.SharedSecret, recovered));
            CryptographicOperations.ZeroMemory(recovered);
        }
    }

    // ---- CIRCL x509 fixtures (real id-XWing OID) -----------------------

    [Fact]
    public void CirclSpkiFixture_Imports_AndReencodesByteForByte()
    {
        var spkiDer = ReadPemDer("xwing.pub");
        var pub = HybridKemPublicKey.ImportSubjectPublicKeyInfo(spkiDer);
        Assert.Equal(HybridKemAlgorithm.XWing, pub.Algorithm);

        // Our encoder must reproduce CIRCL's DER exactly.
        Assert.Equal(spkiDer, pub.ExportSubjectPublicKeyInfo());
    }

    [Fact]
    public void CirclPkcs8Fixture_Imports_AndReencodesByteForByte()
    {
        var pkcs8Der = ReadPemDer("xwing.priv");
        using var priv = HybridKemPrivateKey.ImportPkcs8PrivateKey(pkcs8Der);
        Assert.Equal(HybridKemAlgorithm.XWing, priv.Algorithm);

        // The fixture was generated by CIRCL from the seed 000102…1e1f.
        var expectedSeed = new byte[32];
        for (var i = 0; i < expectedSeed.Length; i++) { expectedSeed[i] = (byte)i; }
        var wire = priv.Export();
        Assert.Equal(WithAlgId(expectedSeed), wire);
        CryptographicOperations.ZeroMemory(wire);

        Assert.Equal(pkcs8Der, priv.ExportPkcs8PrivateKey());
    }

    [Fact]
    public void CirclFixturePair_EncapDecap_RoundTrips()
    {
        // The .pub and .priv fixtures must form a working pair through
        // our implementation (public key derived by CIRCL, seed expansion
        // done by us at decapsulation time).
        var pub = HybridKemPublicKey.ImportSubjectPublicKeyInfo(ReadPemDer("xwing.pub"));
        using var priv = HybridKemPrivateKey.ImportPkcs8PrivateKey(ReadPemDer("xwing.priv"));
        using var enc = HybridKem.Encapsulate(pub);
        var recovered = HybridKem.Decapsulate(priv, enc.Ciphertext);
        Assert.True(CryptographicOperations.FixedTimeEquals(enc.SharedSecret, recovered));
        CryptographicOperations.ZeroMemory(recovered);
    }

    // ---- Generate / serialize / use ------------------------------------

    [Fact]
    public void GenerateKeyPair_XWing_FullLifecycle()
    {
        using var pair = HybridKem.GenerateKeyPair(HybridKemAlgorithm.XWing);
        Assert.Equal(HybridKemAlgorithm.XWing, pair.PublicKey.Algorithm);
        Assert.Equal(HybridKemAlgorithm.XWing, pair.PrivateKey.Algorithm);

        var pubBytes = pair.PublicKey.Export();
        Assert.Equal(1217, pubBytes.Length);
        Assert.Equal(0x03, pubBytes[0]);
        var privBytes = pair.PrivateKey.Export();
        Assert.Equal(33, privBytes.Length);
        Assert.Equal(0x03, privBytes[0]);
        CryptographicOperations.ZeroMemory(privBytes);

        using var enc = HybridKem.Encapsulate(pair.PublicKey);
        Assert.Equal(1121, enc.Ciphertext.ToBytes().Length);
        var recovered = HybridKem.Decapsulate(pair.PrivateKey, enc.Ciphertext);
        Assert.True(CryptographicOperations.FixedTimeEquals(enc.SharedSecret, recovered));
        CryptographicOperations.ZeroMemory(recovered);
    }

    [Fact]
    public void GenerateKeyPair_XWing_PemRoundTrip()
    {
        using var pair = HybridKem.GenerateKeyPair(HybridKemAlgorithm.XWing);
        var pub2 = HybridKemPublicKey.ImportPem(pair.PublicKey.ExportPem());
        using var priv2 = HybridKemPrivateKey.ImportPem(pair.PrivateKey.ExportPem());
        Assert.Equal(HybridKemAlgorithm.XWing, pub2.Algorithm);
        Assert.Equal(HybridKemAlgorithm.XWing, priv2.Algorithm);

        using var enc = HybridKem.Encapsulate(pub2);
        var recovered = HybridKem.Decapsulate(priv2, enc.Ciphertext);
        Assert.True(CryptographicOperations.FixedTimeEquals(enc.SharedSecret, recovered));
        CryptographicOperations.ZeroMemory(recovered);
    }

    [Fact]
    public void GenerateKeyPair_XWing_SerializedPrivateKeyRoundTripsThroughImport()
    {
        using var pair = HybridKem.GenerateKeyPair(HybridKemAlgorithm.XWing);
        using var enc = HybridKem.Encapsulate(pair.PublicKey);

        var privBytes = pair.PrivateKey.Export();
        using var reimported = HybridKemPrivateKey.Import(privBytes);
        CryptographicOperations.ZeroMemory(privBytes);

        var recovered = HybridKem.Decapsulate(reimported, enc.Ciphertext);
        Assert.True(CryptographicOperations.FixedTimeEquals(enc.SharedSecret, recovered));
        CryptographicOperations.ZeroMemory(recovered);
    }

    // ---- Fail-closed ----------------------------------------------------

    [Fact]
    public void Import_XWingPrivateKey_WrongLength_Throws()
    {
        // A v1-sized blob (2433) carrying the X-Wing algorithm-id is invalid.
        var blob = new byte[2433];
        blob[0] = 0x03;
        var ex = Assert.Throws<HybridKeyParseException>(() => HybridKemPrivateKey.Import(blob));
        Assert.Equal(HybridFailureReason.InvalidLength, ex.Reason);

        var truncated = new byte[32];
        truncated[0] = 0x03;
        Assert.Throws<HybridKeyParseException>(() => HybridKemPrivateKey.Import(truncated));
    }

    [Fact]
    public void Import_EmptyPrivateKey_Throws()
    {
        Assert.Throws<HybridKeyParseException>(() => HybridKemPrivateKey.Import(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void Import_XWingPublicKey_WrongLength_Throws()
    {
        var truncated = new byte[1216]; // missing one byte
        truncated[0] = 0x03;
        var ex = Assert.Throws<HybridKeyParseException>(() => HybridKemPublicKey.Import(truncated));
        Assert.Equal(HybridFailureReason.InvalidLength, ex.Reason);
    }

    [Fact]
    public void Decapsulate_XWing_TamperedCiphertext_DivergesViaImplicitRejection()
    {
        var vectors = LoadVectors();
        var v = vectors[0];
        using var priv = HybridKemPrivateKey.Import(WithAlgId(v.Sk));

        var tamperedWire = WithAlgId(v.Ct);
        tamperedWire[100] ^= 0x01; // flip a bit inside ct_M
        var tampered = HybridKemCiphertext.FromBytes(tamperedWire);

        // FIPS 203 implicit rejection: decapsulation succeeds but yields a
        // pseudorandom secret that does not match the KAT value.
        var ss = HybridKem.Decapsulate(priv, tampered);
        Assert.False(CryptographicOperations.FixedTimeEquals(v.Ss, ss),
            "tampered ciphertext must not reproduce the official shared secret");
        CryptographicOperations.ZeroMemory(ss);
    }

    [Fact]
    public void Decapsulate_AlgorithmMismatch_Throws()
    {
        using var v1Pair = HybridKem.GenerateKeyPair(HybridKemAlgorithm.X25519MlKem768);
        using var xwingPair = HybridKem.GenerateKeyPair(HybridKemAlgorithm.XWing);
        using var enc = HybridKem.Encapsulate(xwingPair.PublicKey);

        Assert.Throws<InvalidCiphertextException>(() =>
            HybridKem.Decapsulate(v1Pair.PrivateKey, enc.Ciphertext));
    }

    [Fact]
    public void XWingPrivateKey_UseAfterDispose_Throws_AndDoubleDisposeIsSafe()
    {
        var pair = HybridKem.GenerateKeyPair(HybridKemAlgorithm.XWing);
        using var enc = HybridKem.Encapsulate(pair.PublicKey);
        pair.Dispose();
        pair.Dispose(); // double dispose must be a no-op

        Assert.Throws<ObjectDisposedException>(() =>
            HybridKem.Decapsulate(pair.PrivateKey, enc.Ciphertext));
    }

    [Fact]
    public void ImportSpki_XWingOid_WrongInnerLength_Throws()
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier("1.3.6.1.4.1.62253.25722");
            }
            w.WriteBitString(new byte[100]); // not 1216
        }
        var ex = Assert.Throws<HybridKeyParseException>(() =>
            HybridKemPublicKey.ImportSubjectPublicKeyInfo(w.Encode()));
        Assert.Equal(HybridFailureReason.InvalidLength, ex.Reason);
    }

    [Fact]
    public void ImportPkcs8_XWingOid_WrongInnerLength_Throws()
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            w.WriteInteger(0);
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier("1.3.6.1.4.1.62253.25722");
            }
            w.WriteOctetString(new byte[31]); // not 32
        }
        var ex = Assert.Throws<HybridKeyParseException>(() =>
            HybridKemPrivateKey.ImportPkcs8PrivateKey(w.Encode()));
        Assert.Equal(HybridFailureReason.InvalidLength, ex.Reason);
    }

    [Fact]
    public void XWing_WireFormat_IsPqFirst_UnlikeAlgorithm2()
    {
        // 0x02 and 0x03 share total sizes but not component order. Verify
        // PQ-first for 0x03 by checking that the X25519 public key (last 32
        // bytes for 0x03) round-trips into the same encapsulation flow.
        var v = LoadVectors()[0];
        var pub = HybridKemPublicKey.Import(WithAlgId(v.Pk));
        var exported = pub.Export();

        // pk_X is the LAST 32 bytes of the IETF encoding.
        Assert.Equal(v.Pk.AsSpan(1184, 32).ToArray(), exported.AsSpan(1185, 32).ToArray());
        // pk_M is the FIRST 1184 bytes.
        Assert.Equal(v.Pk.AsSpan(0, 1184).ToArray(), exported.AsSpan(1, 1184).ToArray());
    }
}
