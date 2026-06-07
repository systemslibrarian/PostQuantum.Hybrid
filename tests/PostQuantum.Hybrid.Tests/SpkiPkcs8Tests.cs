using System.Security.Cryptography;
using Xunit;

namespace PostQuantum.Hybrid.Tests;

/// <summary>
/// Round-trip tests for the SPKI / PKCS#8 codec. The OIDs are
/// PostQuantum.Hybrid-specific placeholders (preview) — these tests
/// only assert that what we encode we can decode, plus that the
/// structural framing follows X.509 SPKI / PKCS#8 v1 closely enough
/// that the standard <c>System.Security.Cryptography.Pem*</c> /
/// <c>Asn1*</c> helpers will accept it.
/// </summary>
public class SpkiPkcs8Tests
{
    [Fact]
    public void Kem_PublicKey_SpkiRoundTrip()
    {
        using var pair = HybridKem.GenerateKeyPair();
        var spki = pair.PublicKey.ExportSubjectPublicKeyInfo();
        var imported = HybridKemPublicKey.ImportSubjectPublicKeyInfo(spki);
        Assert.Equal(pair.PublicKey.Export(), imported.Export());
    }

    [Fact]
    public void Kem_PublicKey_XWing_SpkiRoundTrip()
    {
        using var pair = HybridKem.GenerateKeyPair(HybridKemAlgorithm.X25519MlKem768XWing);
        var spki = pair.PublicKey.ExportSubjectPublicKeyInfo();
        var imported = HybridKemPublicKey.ImportSubjectPublicKeyInfo(spki);
        Assert.Equal(HybridKemAlgorithm.X25519MlKem768XWing, imported.Algorithm);
        Assert.Equal(pair.PublicKey.Export(), imported.Export());
    }

    [Fact]
    public void Kem_PrivateKey_Pkcs8RoundTrip()
    {
        using var pair = HybridKem.GenerateKeyPair();
        var pkcs8 = pair.PrivateKey.ExportPkcs8PrivateKey();
        try
        {
            using var imported = HybridKemPrivateKey.ImportPkcs8PrivateKey(pkcs8);
            // Use both halves through Encapsulate/Decapsulate to prove the import
            // produced semantically equivalent material.
            using var enc = HybridKem.Encapsulate(pair.PublicKey);
            var recovered = HybridKem.Decapsulate(imported, enc.Ciphertext);
            Assert.True(CryptographicOperations.FixedTimeEquals(enc.SharedSecret, recovered));
            CryptographicOperations.ZeroMemory(recovered);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs8);
        }
    }

    [Fact]
    public void Signature_PublicKey_SpkiRoundTrip()
    {
        using var pair = HybridSignature.GenerateKeyPair();
        var spki = pair.PublicKey.ExportSubjectPublicKeyInfo();
        var imported = HybridSignaturePublicKey.ImportSubjectPublicKeyInfo(spki);
        Assert.Equal(pair.PublicKey.Export(), imported.Export());
    }

    [Fact]
    public void Signature_PrivateKey_Pkcs8RoundTrip()
    {
        using var pair = HybridSignature.GenerateKeyPair();
        var pkcs8 = pair.PrivateKey.ExportPkcs8PrivateKey();
        try
        {
            using var imported = HybridSignaturePrivateKey.ImportPkcs8PrivateKey(pkcs8);
            var message = "round trip"u8.ToArray();
            var sig = HybridSignature.Sign(imported, message);
            Assert.True(HybridSignature.Verify(pair.PublicKey, message, sig));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs8);
        }
    }

    [Fact]
    public void Spki_RejectsWrongTopLevelOid()
    {
        // Hand-craft a SubjectPublicKeyInfo with an unrelated OID
        // (RSA encryption) and confirm we refuse to decode it.
        // SEQUENCE { SEQUENCE { OID rsaEncryption } BIT STRING (0x00) }
        var w = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier("1.2.840.113549.1.1.1");
                w.WriteNull();
            }
            w.WriteBitString(new byte[] { 0x00 });
        }
        var bytes = w.Encode();

        Assert.Throws<HybridKeyParseException>(
            () => HybridKemPublicKey.ImportSubjectPublicKeyInfo(bytes));
    }

    [Fact]
    public void Spki_StructureIsValidDer()
    {
        // Confirm what we emit parses back as a DER SubjectPublicKeyInfo
        // through System.Formats.Asn1 without help from our codec.
        using var pair = HybridKem.GenerateKeyPair();
        var spki = pair.PublicKey.ExportSubjectPublicKeyInfo();
        var reader = new System.Formats.Asn1.AsnReader(spki, System.Formats.Asn1.AsnEncodingRules.DER);
        var seq = reader.ReadSequence();
        reader.ThrowIfNotEmpty();
        var algId = seq.ReadSequence();
        var oid = algId.ReadObjectIdentifier();
        Assert.StartsWith("1.3.6.1.4.1.32473.", oid);
        // BIT STRING contents must equal pair.PublicKey.Export()
        var keyBytes = seq.ReadBitString(out var unusedBits);
        Assert.Equal(0, unusedBits);
        Assert.Equal(pair.PublicKey.Export(), keyBytes);
    }
}
