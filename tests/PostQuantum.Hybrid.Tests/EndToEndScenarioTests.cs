using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace PostQuantum.Hybrid.Tests;

/// <summary>
/// Integration scenarios that combine KEM and signatures the way real
/// applications will. Mirror the patterns in samples/SecureMessenger.
/// </summary>
public class EndToEndScenarioTests
{
    [Fact]
    public void KemThenAesGcm_SignedByAlice_DecryptedByBob()
    {
        using var alice = HybridSignature.GenerateKeyPair();
        using var bob = HybridKem.GenerateKeyPair();

        var plaintext = Encoding.UTF8.GetBytes("End-to-end secure message");
        var packet = AliceSendsToBob(plaintext, bob.PublicKey, alice.PrivateKey);
        var recovered = BobReceivesFromAlice(packet, bob.PrivateKey, alice.PublicKey);
        Assert.Equal(plaintext, recovered);
    }

    [Fact]
    public void TamperWithKemCiphertext_PacketRejected()
    {
        using var alice = HybridSignature.GenerateKeyPair();
        using var bob = HybridKem.GenerateKeyPair();

        var packet = AliceSendsToBob("payload"u8.ToArray(), bob.PublicKey, alice.PrivateKey);
        packet[200] ^= 0xFF; // somewhere in the KEM ciphertext, before the signature
        Assert.ThrowsAny<CryptographicException>(() =>
            BobReceivesFromAlice(packet, bob.PrivateKey, alice.PublicKey));
    }

    [Fact]
    public void TamperWithSignature_PacketRejected()
    {
        using var alice = HybridSignature.GenerateKeyPair();
        using var bob = HybridKem.GenerateKeyPair();

        var packet = AliceSendsToBob("payload"u8.ToArray(), bob.PublicKey, alice.PrivateKey);
        packet[packet.Length - 50] ^= 0xFF; // somewhere in the sig (last 3374 B)
        Assert.ThrowsAny<CryptographicException>(() =>
            BobReceivesFromAlice(packet, bob.PrivateKey, alice.PublicKey));
    }

    [Fact]
    public void SignedDocumentScenario_RoundTrips()
    {
        using var publisher = HybridSignature.GenerateKeyPair();

        var doc = Encoding.UTF8.GetBytes("release v1.0.0\n- initial");
        var sig = HybridSignature.Sign(publisher.PrivateKey, doc);

        // Verifier holds only the public key + doc + sig.
        var publicKey = HybridSignaturePublicKey.Import(publisher.PublicKey.Export());
        Assert.True(HybridSignature.Verify(publicKey, doc, sig));
    }

    [Fact]
    public void KeyAtRestScenario_PemSurvivesRoundTripThroughString()
    {
        using var pair = HybridSignature.GenerateKeyPair();
        var pem = pair.PrivateKey.ExportPem();

        // Simulate writing/reading via a transport that normalizes newlines.
        var normalized = pem.Replace("\n", "\r\n");

        using var reloaded = HybridSignaturePrivateKey.ImportPem(normalized);
        var msg = "after persistence"u8.ToArray();
        var sig = HybridSignature.Sign(reloaded, msg);
        Assert.True(HybridSignature.Verify(pair.PublicKey, msg, sig));
    }

    // ---- Helpers mirror samples/SecureMessenger but trimmed for assertions. ----

    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int KemCtSize = 1121;
    private const int HybridSigSize = 3374;

    private static byte[] AliceSendsToBob(
        ReadOnlySpan<byte> plaintext,
        HybridKemPublicKey bobPub,
        HybridSignaturePrivateKey alicePriv)
    {
        using var enc = HybridKem.Encapsulate(bobPub);
        var kemCt = enc.Ciphertext.ToBytes();
        var aesKey = Derive(enc.SharedSecret, kemCt);

        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];
        using (var aes = new AesGcm(aesKey, TagSize))
        {
            aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData: kemCt);
        }

        // tbs = kemCt || nonce || ciphertext || tag
        var tbs = new byte[kemCt.Length + NonceSize + ciphertext.Length + TagSize];
        var offset = 0;
        kemCt.CopyTo(tbs, offset); offset += kemCt.Length;
        nonce.CopyTo(tbs, offset); offset += NonceSize;
        ciphertext.CopyTo(tbs, offset); offset += ciphertext.Length;
        tag.CopyTo(tbs, offset);

        var sig = HybridSignature.Sign(alicePriv, tbs);
        var packet = new byte[tbs.Length + sig.Length];
        tbs.CopyTo(packet, 0);
        sig.CopyTo(packet, tbs.Length);
        return packet;
    }

    private static byte[] BobReceivesFromAlice(
        ReadOnlySpan<byte> packet,
        HybridKemPrivateKey bobPriv,
        HybridSignaturePublicKey alicePub)
    {
        var tbsLen = packet.Length - HybridSigSize;
        var tbs = packet[..tbsLen];
        var sig = packet[tbsLen..];

        if (!HybridSignature.Verify(alicePub, tbs, sig))
        {
            throw new CryptographicException("Signature invalid");
        }

        var kemCt = tbs[..KemCtSize];
        var nonce = tbs.Slice(KemCtSize, NonceSize);
        var aesCtLen = tbsLen - KemCtSize - NonceSize - TagSize;
        var aesCt = tbs.Slice(KemCtSize + NonceSize, aesCtLen);
        var tag = tbs.Slice(KemCtSize + NonceSize + aesCtLen, TagSize);

        var ss = HybridKem.Decapsulate(bobPriv, kemCt);
        var aesKey = Derive(ss, kemCt);

        var plaintext = new byte[aesCtLen];
        using var aes = new AesGcm(aesKey, TagSize);
        aes.Decrypt(nonce, aesCt, tag, plaintext, associatedData: kemCt);
        return plaintext;
    }

    private static byte[] Derive(ReadOnlySpan<byte> sharedSecret, ReadOnlySpan<byte> kemCiphertext)
    {
        var info = new byte[Encoding.ASCII.GetByteCount("test-derive ") + kemCiphertext.Length];
        Encoding.ASCII.GetBytes("test-derive ").CopyTo(info, 0);
        kemCiphertext.CopyTo(info.AsSpan(Encoding.ASCII.GetByteCount("test-derive ")));
        var key = new byte[32];
        HKDF.Expand(HashAlgorithmName.SHA256, sharedSecret, key, info);
        return key;
    }
}
