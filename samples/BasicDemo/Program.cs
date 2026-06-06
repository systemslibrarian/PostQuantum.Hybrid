using System.Security.Cryptography;
using System.Text;
using PostQuantum.Hybrid;

Console.WriteLine("PostQuantum.Hybrid — sample");
Console.WriteLine($"Runtime: {System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}\n");

KemDemo();
Console.WriteLine();
SignatureDemo();

static void KemDemo()
{
    Console.WriteLine("=== Hybrid KEM (X25519 + ML-KEM-768) ===");

    // Alice generates a hybrid KEM key pair and publishes her public key.
    using var alice = HybridKem.GenerateKeyPair();
    Console.WriteLine($"Alice public key:  {alice.PublicKey.Export().Length,5} bytes");
    Console.WriteLine($"Alice private key: {alice.PrivateKey.Export().Length,5} bytes");

    // Bob encapsulates a shared secret against Alice's public key.
    using var encapsulation = HybridKem.Encapsulate(alice.PublicKey);
    Console.WriteLine($"Ciphertext:        {encapsulation.Ciphertext.ToBytes().Length,5} bytes");
    Console.WriteLine($"Bob's shared:      {Hex(encapsulation.SharedSecret)}");

    // Alice decapsulates to recover the same shared secret.
    var aliceSecret = HybridKem.Decapsulate(alice.PrivateKey, encapsulation.Ciphertext);
    Console.WriteLine($"Alice's shared:    {Hex(aliceSecret)}");

    Console.WriteLine($"Match: {CryptographicOperations.FixedTimeEquals(encapsulation.SharedSecret, aliceSecret)}");
}

static void SignatureDemo()
{
    Console.WriteLine("=== Hybrid Signatures (Ed25519 + ML-DSA-65) ===");

    using var signer = HybridSignature.GenerateKeyPair();
    Console.WriteLine($"Public key:  {signer.PublicKey.Export().Length,5} bytes");
    Console.WriteLine($"Private key: {signer.PrivateKey.Export().Length,5} bytes");

    var message = Encoding.UTF8.GetBytes("Hello, post-quantum world!");
    var signature = HybridSignature.Sign(signer.PrivateKey, message);
    Console.WriteLine($"Signature:   {signature.Length,5} bytes");

    var valid = HybridSignature.Verify(signer.PublicKey, message, signature);
    Console.WriteLine($"Verify (good message): {valid}");

    var tampered = Encoding.UTF8.GetBytes("Hello, post-quantum world?");
    var tamperedValid = HybridSignature.Verify(signer.PublicKey, tampered, signature);
    Console.WriteLine($"Verify (tampered):     {tamperedValid}");

    // PEM round-trip
    var pubPem = signer.PublicKey.ExportPem();
    Console.WriteLine();
    Console.WriteLine("Public key (PEM):");
    Console.Write(pubPem);
}

static string Hex(ReadOnlySpan<byte> bytes)
{
    var sb = new StringBuilder(bytes.Length * 2);
    foreach (var b in bytes)
    {
        sb.Append(b.ToString("x2"));
    }
    return sb.ToString();
}
