using System.Security.Cryptography;
using System.Text;
using PostQuantum.Hybrid;

// =============================================================================
// PostQuantum.Hybrid starter — hybrid KEM + signature in one short demo.
//
// Replace this body with your application logic. Keep the `using` declarations
// on disposable types (HybridKemKeyPair, HybridKemPrivateKey,
// HybridKemEncapsulationResult, HybridSignatureKeyPair, HybridSignaturePrivateKey)
// — the PostQuantum.Hybrid.Analyzers package will flag any you forget.
// =============================================================================

KemDemo();
Console.WriteLine();
SignatureDemo();

static void KemDemo()
{
    Console.WriteLine("=== Hybrid KEM (X25519 + ML-KEM-768) ===");

    using var recipient = HybridKem.GenerateKeyPair();
    using var encapsulation = HybridKem.Encapsulate(recipient.PublicKey);
    var sharedSecret = HybridKem.Decapsulate(recipient.PrivateKey, encapsulation.Ciphertext);

    Console.WriteLine($"Public key:    {recipient.PublicKey.Export().Length,5} bytes");
    Console.WriteLine($"Ciphertext:    {encapsulation.Ciphertext.ToBytes().Length,5} bytes");
    Console.WriteLine($"Shared secret: {encapsulation.SharedSecret.Length,5} bytes");
    Console.WriteLine($"Match:         {CryptographicOperations.FixedTimeEquals(encapsulation.SharedSecret, sharedSecret)}");
}

static void SignatureDemo()
{
    Console.WriteLine("=== Hybrid Signature (Ed25519 + ML-DSA-65) ===");

    using var signer = HybridSignature.GenerateKeyPair();
    var message = Encoding.UTF8.GetBytes("Hello, post-quantum world!");
    var signature = HybridSignature.Sign(signer.PrivateKey, message);
    var valid = HybridSignature.Verify(signer.PublicKey, message, signature);

    Console.WriteLine($"Public key: {signer.PublicKey.Export().Length,5} bytes");
    Console.WriteLine($"Signature:  {signature.Length,5} bytes");
    Console.WriteLine($"Verified:   {valid}");
}
