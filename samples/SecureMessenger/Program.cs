// =============================================================================
// PostQuantum.Hybrid sample: end-to-end signed-and-encrypted messaging.
//
// This combines BOTH hybrid primitives in a realistic flow. It is the
// most complete sample in the repo and the best place to copy from when
// you need authenticated confidentiality (i.e. the recipient learns
// both "what was said" and "who said it").
//
// Wire layout (one packet from Alice to Bob):
//
//   ┌─────────────────────────── to-be-signed (tbs) ─────────────────────────┐
//   │  KEM_ct (1121) │ nonce (12) │ ct_len (4 LE) │ ciphertext │ tag (16) │
//   └────────────────────────────────────────────────────────────────────────┘
//   │ hybrid signature (3374) │
//   └─────────────────────────┘
//
// Why each piece is there:
//   • KEM_ct          — the post-quantum + classical key exchange material.
//   • nonce           — fresh AES-GCM nonce, unique per packet.
//   • ct_len + ct     — the actual encrypted payload.
//   • tag             — AES-GCM authentication tag binding key, nonce, ct, and AAD.
//   • hybrid signature — proves Alice authored the tbs *before* Bob acts on it.
//
// Two non-obvious patterns:
//   1. Verify BEFORE decrypt. Bob runs HybridSignature.Verify on the
//      tbs first; if that fails he never decapsulates or decrypts. The
//      PQH003 analyzer enforces this ordering at build time. Acting on
//      unauthenticated input — even just decapsulating it — widens the
//      attack surface (timing side channels, exception oracles, etc.).
//   2. KEM ct binds into BOTH the AEAD AAD and the HKDF info. Either
//      one alone is sufficient; using both means a swapped KEM ct is
//      rejected at AEAD decryption AND yields a different derived key.
//      Defense in depth.
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
// Both pairs use `using` so the private keys are zeroed on dispose.
// PQH001 flags any local of these types declared without it.
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
// Flip a byte inside the ciphertext portion. Verify catches it because
// the signature was over the full tbs (which includes the ciphertext).
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
    // Encapsulate, then derive an AES key from the resulting hybrid
    // shared secret. The `using` zeroes the secret buffer on scope exit;
    // we use `Secret` (the typed wrapper) instead of `SharedSecret`
    // (byte[]) so the secret flows directly into HKDF via implicit span
    // conversion, with no ToArray() boilerplate.
    using var encapsulation = HybridKem.Encapsulate(bobPublicKey);
    var kemCt = encapsulation.Ciphertext.ToBytes();
    var aesKey = DeriveAesKey(encapsulation.Secret, kemCt);

    var nonce = RandomNumberGenerator.GetBytes(NonceSize);
    var ciphertext = new byte[plaintext.Length];
    var tag = new byte[TagSize];
    using (var aes = new AesGcm(aesKey, TagSize))
    {
        // Bind kemCt into the AEAD as associatedData. PQH005 enforces
        // this for any AesGcm call inside a method that uses HybridKem.
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData: kemCt);
    }
    CryptographicOperations.ZeroMemory(aesKey);

    // Build the to-be-signed block: KEM_ct || nonce || AES_ct_len(LE u32) || AES_ct || tag.
    // Note: we sign the *ciphertext*, not the plaintext. That means
    // verify-before-decrypt is sufficient — Bob doesn't need to decrypt
    // anything to learn whether Alice authored this packet.
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

    // Verify BEFORE doing anything else. PQH003 enforces this ordering
    // at build time. Once verification passes we know the tbs was
    // authored by Alice and has not been altered in transit; only then
    // do we touch the KEM and AEAD with it.
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

    // Non-throwing decap. The signature already proved authenticity,
    // so a parse failure here is "this was definitely an attacker"
    // (or a bug) — surface it as a clean cryptographic rejection.
    if (!HybridKem.TryDecapsulate(bobPrivateKey, kemCt, out var sharedSecret))
    {
        throw new CryptographicException("Hybrid KEM decapsulation failed after a valid signature — input is malformed.");
    }
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
    // Two-layer defense for the KEM ciphertext:
    //  • bound into HKDF info — a swapped ct yields a different AES key.
    //  • bound into AEAD AAD — a swapped ct also breaks the tag.
    var infoPrefix = Encoding.ASCII.GetBytes("PostQuantum.Hybrid SecureMessenger v1 AES-256-GCM");
    var info = new byte[infoPrefix.Length + kemCiphertext.Length];
    infoPrefix.CopyTo(info, 0);
    kemCiphertext.CopyTo(info.AsSpan(infoPrefix.Length));
    var key = new byte[32];
    HKDF.Expand(HashAlgorithmName.SHA256, sharedSecret, key, info);
    return key;
}
