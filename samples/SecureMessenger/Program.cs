// =============================================================================
// PostQuantum.Hybrid sample: end-to-end signed-and-encrypted messaging.
//
// Combines BOTH hybrid primitives in a realistic flow:
//
//   Setup: Alice publishes her signing-public-key, Bob publishes his KEM-
//          public-key.
//
//   Alice -> Bob:
//     1. Alice encapsulates against Bob's KEM public key, derives an AES key.
//     2. Alice encrypts the message body with AES-GCM. The AAD includes the
//        KEM ciphertext to bind the ciphertext to this exchange.
//     3. Alice signs (KEM_ciphertext || nonce || AES_ciphertext || tag) so
//        Bob can verify both authenticity (from Alice) and integrity.
//     4. Alice transmits { KEM_ct, nonce, AES_ct, tag, signature }.
//
//   Bob:
//     1. Verifies the signature with Alice's public key. If invalid, abort.
//     2. Decapsulates the KEM ciphertext with his private key.
//     3. Decrypts the AES-GCM body.
// =============================================================================

using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using PostQuantum.Hybrid;

const int NonceSize = 12;
const int TagSize = 16;
const int KemCtSize = 1121;
const int HybridSigSize = 3374;

Console.WriteLine("PostQuantum.Hybrid sample: signed + encrypted messaging\n");

// ----- One-time setup: each party generates their key material. -----
using var aliceSigning = HybridSignature.GenerateKeyPair();
using var bobKem = HybridKem.GenerateKeyPair();

Console.WriteLine($"Alice signing pub: {aliceSigning.PublicKey.Export().Length} bytes");
Console.WriteLine($"Bob KEM pub:       {bobKem.PublicKey.Export().Length} bytes\n");

// ----- Alice -> Bob. -----
var plaintext = Encoding.UTF8.GetBytes(
    "Bob, the launch is approved for Friday. Confidential. — Alice");

var packet = AliceSendsToBob(plaintext, bobKem.PublicKey, aliceSigning.PrivateKey);
Console.WriteLine($"Wire packet:       {packet.Length} bytes (plaintext {plaintext.Length} B)");

// ----- Bob receives. -----
var recovered = BobReceivesFromAlice(packet, bobKem.PrivateKey, aliceSigning.PublicKey);
Console.WriteLine($"Recovered:         \"{Encoding.UTF8.GetString(recovered)}\"\n");

// ----- Tamper-detection test. -----
packet[KemCtSize + NonceSize + 2] ^= 0xFF;
try
{
    BobReceivesFromAlice(packet, bobKem.PrivateKey, aliceSigning.PublicKey);
    Console.WriteLine("Tampered packet accepted — bug!");
}
catch (CryptographicException ex)
{
    Console.WriteLine($"Tampered packet rejected: {ex.Message}");
}

static byte[] AliceSendsToBob(
    ReadOnlySpan<byte> plaintext,
    HybridKemPublicKey bobPublicKey,
    HybridSignaturePrivateKey alicePrivateKey)
{
    using var encapsulation = HybridKem.Encapsulate(bobPublicKey);
    var kemCt = encapsulation.Ciphertext.ToBytes();
    var aesKey = DeriveAesKey(encapsulation.SharedSecret, kemCt);

    var nonce = RandomNumberGenerator.GetBytes(NonceSize);
    var ciphertext = new byte[plaintext.Length];
    var tag = new byte[TagSize];
    using (var aes = new AesGcm(aesKey, TagSize))
    {
        // Bind the KEM ciphertext into the AEAD as associated data so
        // any rearrangement breaks decryption.
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData: kemCt);
    }
    CryptographicOperations.ZeroMemory(aesKey);

    // Build the to-be-signed block: KEM_ct || nonce || AES_ct_len(LE u32) || AES_ct || tag.
    var tbs = new byte[kemCt.Length + NonceSize + 4 + ciphertext.Length + TagSize];
    var span = tbs.AsSpan();
    var offset = 0;
    kemCt.CopyTo(span[offset..]); offset += kemCt.Length;
    nonce.CopyTo(span[offset..]); offset += NonceSize;
    BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(offset, 4), (uint)ciphertext.Length); offset += 4;
    ciphertext.CopyTo(span[offset..]); offset += ciphertext.Length;
    tag.CopyTo(span[offset..]);

    var signature = HybridSignature.Sign(alicePrivateKey, tbs);

    // Wire format: tbs || signature.
    var packet = new byte[tbs.Length + signature.Length];
    tbs.CopyTo(packet, 0);
    signature.CopyTo(packet, tbs.Length);
    return packet;
}

static byte[] BobReceivesFromAlice(
    ReadOnlySpan<byte> packet,
    HybridKemPrivateKey bobPrivateKey,
    HybridSignaturePublicKey alicePublicKey)
{
    if (packet.Length < KemCtSize + NonceSize + 4 + TagSize + HybridSigSize)
    {
        throw new CryptographicException("Packet too short.");
    }

    var tbsLen = packet.Length - HybridSigSize;
    var tbs = packet[..tbsLen];
    var signature = packet[tbsLen..];

    if (!HybridSignature.Verify(alicePublicKey, tbs, signature))
    {
        throw new CryptographicException("Signature does not validate. Rejecting packet.");
    }

    var kemCt = tbs[..KemCtSize];
    var nonce = tbs.Slice(KemCtSize, NonceSize);
    var aesCtLen = (int)BinaryPrimitives.ReadUInt32LittleEndian(tbs.Slice(KemCtSize + NonceSize, 4));
    var aesCtStart = KemCtSize + NonceSize + 4;
    var aesCt = tbs.Slice(aesCtStart, aesCtLen);
    var tag = tbs.Slice(aesCtStart + aesCtLen, TagSize);

    var sharedSecret = HybridKem.Decapsulate(bobPrivateKey, kemCt);
    var aesKey = DeriveAesKey(sharedSecret, kemCt);
    CryptographicOperations.ZeroMemory(sharedSecret);

    var plaintext = new byte[aesCtLen];
    using (var aes = new AesGcm(aesKey, TagSize))
    {
        aes.Decrypt(nonce, aesCt, tag, plaintext, associatedData: kemCt);
    }
    CryptographicOperations.ZeroMemory(aesKey);
    return plaintext;
}

static byte[] DeriveAesKey(ReadOnlySpan<byte> sharedSecret, ReadOnlySpan<byte> kemCiphertext)
{
    var infoPrefix = Encoding.ASCII.GetBytes("PostQuantum.Hybrid SecureMessenger v1 AES-256-GCM");
    var info = new byte[infoPrefix.Length + kemCiphertext.Length];
    infoPrefix.CopyTo(info, 0);
    kemCiphertext.CopyTo(info.AsSpan(infoPrefix.Length));
    var key = new byte[32];
    HKDF.Expand(HashAlgorithmName.SHA256, sharedSecret, key, info);
    return key;
}
