// =============================================================================
// PostQuantum.Hybrid sample: KEM-derived AES-GCM encryption.
//
// This is the canonical real-world use of a KEM: you don't encrypt your message
// directly with the KEM, you use the KEM to derive a symmetric key, then
// encrypt the message with AES-GCM (or ChaCha20-Poly1305). This keeps the
// ciphertext small regardless of how long the message is.
//
// Wire layout of one "encrypted envelope":
//   [ hybrid KEM ciphertext (1121 B) ] [ AES-GCM nonce (12 B) ]
//   [ AES-GCM tag (16 B) ] [ ciphertext (variable) ]
// =============================================================================

using System.Security.Cryptography;
using System.Text;
using PostQuantum.Hybrid;

const int NonceSize = 12;
const int TagSize = 16;
const int KemCtSize = 1121;

Console.WriteLine("PostQuantum.Hybrid sample: KEM -> AES-GCM encryption\n");

// ----- Setup: recipient generates a hybrid KEM key pair. -----
using var recipient = HybridKem.GenerateKeyPair();

// ----- Sender encrypts a message to the recipient's public key. -----
var plaintext = Encoding.UTF8.GetBytes(
    "This is a confidential message protected by both X25519 and ML-KEM-768. " +
    "Either primitive holding is sufficient for the message to stay secret.");
byte[] envelope = EncryptToRecipient(recipient.PublicKey, plaintext);

Console.WriteLine($"Plaintext:      {plaintext.Length} bytes");
Console.WriteLine($"Envelope:       {envelope.Length} bytes (overhead {envelope.Length - plaintext.Length} B)");

// ----- Recipient decrypts. -----
byte[] recovered = DecryptFromSender(recipient.PrivateKey, envelope);
Console.WriteLine($"Recovered:      \"{Encoding.UTF8.GetString(recovered)}\"\n");

// ----- Demonstrate tamper detection. -----
envelope[envelope.Length - 5] ^= 0xFF;
try
{
    DecryptFromSender(recipient.PrivateKey, envelope);
    Console.WriteLine("Tampered envelope decrypted — this should NOT happen.");
}
catch (CryptographicException ex)
{
    Console.WriteLine($"Tampered envelope rejected by AES-GCM: {ex.Message}");
}

static byte[] EncryptToRecipient(HybridKemPublicKey recipientPublicKey, ReadOnlySpan<byte> plaintext)
{
    using var encapsulation = HybridKem.Encapsulate(recipientPublicKey);
    var aesKey = DeriveAesKey(encapsulation.SharedSecret);

    var nonce = RandomNumberGenerator.GetBytes(NonceSize);
    var ciphertext = new byte[plaintext.Length];
    var tag = new byte[TagSize];

    using (var aes = new AesGcm(aesKey, TagSize))
    {
        aes.Encrypt(nonce, plaintext, ciphertext, tag);
    }

    var kemCt = encapsulation.Ciphertext.ToBytes();
    var envelope = new byte[kemCt.Length + NonceSize + TagSize + ciphertext.Length];
    var offset = 0;
    kemCt.CopyTo(envelope.AsSpan(offset)); offset += kemCt.Length;
    nonce.CopyTo(envelope.AsSpan(offset)); offset += NonceSize;
    tag.CopyTo(envelope.AsSpan(offset)); offset += TagSize;
    ciphertext.CopyTo(envelope.AsSpan(offset));

    CryptographicOperations.ZeroMemory(aesKey);
    return envelope;
}

static byte[] DecryptFromSender(HybridKemPrivateKey recipientPrivateKey, ReadOnlySpan<byte> envelope)
{
    if (envelope.Length < KemCtSize + NonceSize + TagSize)
    {
        throw new CryptographicException("Envelope is too short to be valid.");
    }

    var kemCt = envelope[..KemCtSize];
    var nonce = envelope.Slice(KemCtSize, NonceSize);
    var tag = envelope.Slice(KemCtSize + NonceSize, TagSize);
    var ciphertext = envelope[(KemCtSize + NonceSize + TagSize)..];

    var sharedSecret = HybridKem.Decapsulate(recipientPrivateKey, kemCt);
    var aesKey = DeriveAesKey(sharedSecret);
    CryptographicOperations.ZeroMemory(sharedSecret);

    var plaintext = new byte[ciphertext.Length];
    using (var aes = new AesGcm(aesKey, TagSize))
    {
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
    }
    CryptographicOperations.ZeroMemory(aesKey);
    return plaintext;
}

static byte[] DeriveAesKey(ReadOnlySpan<byte> sharedSecret)
{
    // The KEM already returns a uniform 32-byte secret; a second HKDF "expand"
    // with a purpose-specific info gives us domain separation in case we ever
    // derive multiple keys from the same exchange.
    var info = Encoding.ASCII.GetBytes("PostQuantum.Hybrid KemEncryption v1 AES-256-GCM key");
    var key = new byte[32];
    HKDF.Expand(HashAlgorithmName.SHA256, sharedSecret, key, info);
    return key;
}
