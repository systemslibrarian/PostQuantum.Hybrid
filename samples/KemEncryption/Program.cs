// =============================================================================
// PostQuantum.Hybrid sample: KEM-derived AES-GCM encryption.
//
// This is the canonical real-world use of a KEM: you don't encrypt your
// message directly with the KEM, you use the KEM to derive a symmetric
// key, then encrypt the message with AES-GCM (or ChaCha20-Poly1305).
// That keeps the ciphertext small regardless of how long the message is.
//
// Three things to notice in this sample:
//   1. The shared secret flows through HKDF, never into the AEAD ctor
//      directly. The PQH002 analyzer would flag that misuse at build
//      time; using HKDF gives us domain separation and matches what the
//      KEM was designed to feed into.
//   2. The KEM ciphertext is bound into the AEAD as associatedData. An
//      attacker who swapped one valid ciphertext for another could
//      otherwise re-key the AEAD invisibly — binding the KEM ct closes
//      that door. The PQH005 analyzer enforces this.
//   3. Every sensitive buffer (the derived AES key, the shared secret
//      via the HybridSharedSecret wrapper) is cleared explicitly after
//      use. The buffers we forget would otherwise sit in process memory
//      until GC.
//
// Wire layout of one "encrypted envelope":
//   [ hybrid KEM ciphertext (1121 B) ] [ AES-GCM nonce (12 B) ]
//   [ AES-GCM tag (16 B) ]             [ ciphertext (variable) ]
// =============================================================================

using System.Security.Cryptography;
using System.Text;
using PostQuantum.Hybrid;

const int NonceSize = 12;
const int TagSize = 16;
const int KemCtSize = 1121;

Console.WriteLine("PostQuantum.Hybrid sample: KEM -> AES-GCM encryption\n");

// ----- Setup: recipient generates a hybrid KEM key pair. -----
// The `using` is mandatory — the private key buffers are zeroed on dispose.
// The PQH001 analyzer flags any local of this type that omits `using`.
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

// ----- Demonstrate tamper detection. AES-GCM throws on a bad tag. -----
envelope[^5] ^= 0xFF;
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
    // Encapsulate against the recipient's public key. The returned
    // result owns the shared-secret buffer; `using` zeroes it on scope
    // exit, even if we throw partway through.
    using var encapsulation = HybridKem.Encapsulate(recipientPublicKey);
    var kemCt = encapsulation.Ciphertext.ToBytes();

    // Derive the AES key from the hybrid shared secret. We use the
    // typed `Secret` wrapper instead of the raw `SharedSecret` byte[]:
    // it implicitly converts to ReadOnlySpan<byte>, so it flows
    // straight into HKDF without ToArray() boilerplate, and the
    // wrapper discourages the "just hand it to AesGcm" misuse that
    // PQH002 would flag.
    var aesKey = DeriveAesKey(encapsulation.Secret);

    var nonce = RandomNumberGenerator.GetBytes(NonceSize);
    var ciphertext = new byte[plaintext.Length];
    var tag = new byte[TagSize];

    using (var aes = new AesGcm(aesKey, TagSize))
    {
        // Bind the KEM ciphertext into associatedData. If an attacker
        // ever swaps in a different KEM ct, the AEAD tag will not
        // verify under the resulting (different) key derivation. The
        // PQH005 analyzer enforces this binding.
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData: kemCt);
    }

    var envelope = new byte[kemCt.Length + NonceSize + TagSize + ciphertext.Length];
    var offset = 0;
    kemCt.CopyTo(envelope.AsSpan(offset));      offset += kemCt.Length;
    nonce.CopyTo(envelope.AsSpan(offset));      offset += NonceSize;
    tag.CopyTo(envelope.AsSpan(offset));        offset += TagSize;
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

    // Non-throwing decap at the trust boundary. A malformed kemCt
    // would still pass FIPS-203 implicit rejection (yielding a
    // pseudorandom secret), so the real authentication happens in
    // AesGcm.Decrypt below — but TryDecapsulate cleanly handles the
    // case where the wire-format bytes are the wrong length or
    // carry an unknown algorithm id.
    if (!HybridKem.TryDecapsulate(recipientPrivateKey, kemCt, out var sharedSecret))
    {
        throw new CryptographicException("Hybrid KEM decapsulation rejected the envelope.");
    }

    var aesKey = DeriveAesKey(sharedSecret);
    CryptographicOperations.ZeroMemory(sharedSecret);

    var plaintext = new byte[ciphertext.Length];
    using (var aes = new AesGcm(aesKey, TagSize))
    {
        aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData: kemCt);
    }
    CryptographicOperations.ZeroMemory(aesKey);
    return plaintext;
}

static byte[] DeriveAesKey(ReadOnlySpan<byte> sharedSecret)
{
    // The KEM secret is uniform 32 bytes — coincidentally what AES-256
    // needs — but using it directly loses domain separation. HKDF.Expand
    // with a purpose-specific `info` lets us derive multiple distinct
    // keys from the same exchange in the future without collisions.
    var info = Encoding.ASCII.GetBytes("PostQuantum.Hybrid KemEncryption v1 AES-256-GCM key");
    var key = new byte[32];
    HKDF.Expand(HashAlgorithmName.SHA256, sharedSecret, key, info);
    return key;
}
