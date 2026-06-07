// =============================================================================
// PostQuantum.Hybrid sample: misuse-resistant envelopes.
//
// This is the *recommended* starting point. The other samples (KemEncryption,
// SecureMessenger, LargeFileEncryption) show how a hybrid KEM exchange is
// wired up by hand — KEM → HKDF → AES-GCM with the KEM ciphertext bound
// into associatedData, all the disposal and zeroization rituals. Reading
// them is useful when you need to customize the pipeline.
//
// Reach for this sample first. The `Envelopes` package collapses that
// entire pipeline into ONE method call per direction, with all of the
// safety properties (binding, KDF, AEAD, disposal) baked in:
//
//   • Anonymous:  byte[] envelope = HybridEnvelope.Seal(recipientPub, plain);
//                 byte[] plain    = HybridEnvelope.Open(recipientPriv, envelope);
//
//   • Signed:     byte[] envelope = SignedHybridEnvelope.Seal(senderPriv,
//                                                             recipientPub,
//                                                             plain);
//                 byte[] plain    = SignedHybridEnvelope.Open(senderPub,
//                                                             recipientPriv,
//                                                             envelope);
//
// Wire-format sizes are fixed and documented:
//   • HybridEnvelope.OverheadBytes        = 1150  (version + KEM ct + nonce + tag)
//   • SignedHybridEnvelope.OverheadBytes  = 1150 + 3374 = 4524
//
// =============================================================================

using System.Text;
using PostQuantum.Hybrid;
using PostQuantum.Hybrid.Envelopes;

Console.WriteLine("PostQuantum.Hybrid sample: misuse-resistant envelopes\n");

AnonymousDemo();
Console.WriteLine();
SignedDemo();
Console.WriteLine();
TamperDemo();

static void AnonymousDemo()
{
    Console.WriteLine("=== Anonymous envelope (anyone holding the public key can seal) ===");

    // Generate the recipient's hybrid KEM key pair. `using` is mandatory:
    // PQH001 catches any local of these types declared without it.
    using var recipient = HybridKem.GenerateKeyPair();

    var plaintext = Encoding.UTF8.GetBytes(
        "This is a confidential message. The recipient does not learn who sent it.");

    // Sender side — one call. No HKDF, no AesGcm, no nonce generation,
    // no associatedData binding, no manual zeroization. The Envelopes
    // package does all of it correctly.
    var envelope = HybridEnvelope.Seal(recipient.PublicKey, plaintext);
    Console.WriteLine($"  Plaintext:        {plaintext.Length} bytes");
    Console.WriteLine($"  Envelope:         {envelope.Length} bytes (overhead {envelope.Length - plaintext.Length} B = HybridEnvelope.OverheadBytes)");

    // Recipient side — one call. Throws CryptographicException on any
    // tamper / parse failure.
    var recovered = HybridEnvelope.Open(recipient.PrivateKey, envelope);
    Console.WriteLine($"  Recovered:        \"{Encoding.UTF8.GetString(recovered)}\"");
}

static void SignedDemo()
{
    Console.WriteLine("=== Signed envelope (the recipient also learns who sent it) ===");

    // Sender holds a signature key pair; recipient holds a KEM key pair.
    // In a real deployment the sender's signature public key was
    // distributed out of band (in a manifest, in source control, in a
    // configuration secret, etc.), the same way TLS certificate pinning
    // distributes server keys.
    using var sender = HybridSignature.GenerateKeyPair();
    using var recipient = HybridKem.GenerateKeyPair();

    var plaintext = Encoding.UTF8.GetBytes("Bob — launch approved for Friday. Confidential. — Alice");

    // Sender side — one call signs *and* encrypts. The signature covers
    // the entire inner envelope, so any tamper anywhere in transit is
    // detected before decryption is ever attempted.
    var envelope = SignedHybridEnvelope.Seal(sender.PrivateKey, recipient.PublicKey, plaintext);
    Console.WriteLine($"  Plaintext:        {plaintext.Length} bytes");
    Console.WriteLine($"  Envelope:         {envelope.Length} bytes (overhead {envelope.Length - plaintext.Length} B = SignedHybridEnvelope.OverheadBytes)");

    // Recipient side — verifies the signature THEN unwraps. The
    // verify-before-decapsulate ordering (which the PQH003 analyzer
    // enforces in hand-rolled flows) is baked in here.
    var recovered = SignedHybridEnvelope.Open(sender.PublicKey, recipient.PrivateKey, envelope);
    Console.WriteLine($"  Recovered:        \"{Encoding.UTF8.GetString(recovered)}\"");
}

static void TamperDemo()
{
    Console.WriteLine("=== Tamper rejection ===");

    using var sender = HybridSignature.GenerateKeyPair();
    using var recipient = HybridKem.GenerateKeyPair();

    var plaintext = Encoding.UTF8.GetBytes("must not be altered in transit");
    var envelope = SignedHybridEnvelope.Seal(sender.PrivateKey, recipient.PublicKey, plaintext);

    // Flip a byte inside the encrypted payload. The signature covers
    // the full envelope, so verification fails before decapsulation.
    envelope[^16] ^= 0xFF;

    try
    {
        SignedHybridEnvelope.Open(sender.PublicKey, recipient.PrivateKey, envelope);
        Console.WriteLine("  Tampered envelope accepted — bug!");
    }
    catch (System.Security.Cryptography.CryptographicException ex)
    {
        Console.WriteLine($"  Tampered envelope rejected: {ex.Message}");
    }
}
