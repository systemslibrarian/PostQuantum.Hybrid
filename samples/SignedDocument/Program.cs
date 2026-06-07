// =============================================================================
// PostQuantum.Hybrid sample: detached document signing.
//
// We sign a payload (think: release artifact, configuration file, software
// update) and distribute the public key + signature alongside it. A verifier
// can confirm authenticity using just the public key — without ever holding
// the signing key.
// =============================================================================

using System.Text;
using PostQuantum.Hybrid;

Console.WriteLine("PostQuantum.Hybrid sample: detached document signature\n");

var workDir = Path.Combine(Path.GetTempPath(), "pqh-signed-doc-" + Guid.NewGuid().ToString("N")[..8]);
Directory.CreateDirectory(workDir);

try
{
    var documentPath = Path.Combine(workDir, "release-notes.txt");
    var signaturePath = documentPath + ".sig";
    var publicKeyPath = Path.Combine(workDir, "signer.pub.pem");

    var documentBody = """
        PostQuantum.Hybrid v1.0.0 — release notes
        =========================================
        Initial release of the hybrid post-quantum cryptography library.
        - Hybrid KEM: X25519 + ML-KEM-768
        - Hybrid signatures: Ed25519 + ML-DSA-65
        Targets .NET 8 and .NET 10.
        """;

    Console.WriteLine($"[publisher] writing {Path.GetFileName(documentPath)} ({documentBody.Length} bytes)");
    File.WriteAllText(documentPath, documentBody);

    // ----- Publisher signs and distributes [document, public key, signature]. -----
    using (var publisher = HybridSignature.GenerateKeyPair())
    {
        var documentBytes = File.ReadAllBytes(documentPath);
        var signature = HybridSignature.Sign(publisher.PrivateKey, documentBytes);

        File.WriteAllBytes(signaturePath, signature);
        File.WriteAllText(publicKeyPath, publisher.PublicKey.ExportPem());

        Console.WriteLine($"[publisher] signed -> {Path.GetFileName(signaturePath)} ({signature.Length} bytes)");
        Console.WriteLine($"[publisher] published public key -> {Path.GetFileName(publicKeyPath)}");
        Console.WriteLine("[publisher] private key disposed.\n");
    }

    // ----- Verifier loads only the public artifacts and validates. -----
    // Use TryImportPem at the trust boundary: the public PEM came over
    // the wire (or off disk) and might be malformed. Returning false on
    // parse failure is cleaner than catching CryptographicException.
    {
        if (!HybridSignaturePublicKey.TryImportPem(File.ReadAllText(publicKeyPath), out var publicKey))
        {
            throw new InvalidOperationException(
                $"Refusing to verify against {Path.GetFileName(publicKeyPath)}: PEM parse failed.");
        }
        var documentBytes = File.ReadAllBytes(documentPath);
        var signature = File.ReadAllBytes(signaturePath);

        var ok = HybridSignature.Verify(publicKey, documentBytes, signature);
        Console.WriteLine($"[verifier] signature valid for original document: {ok}");

        // Tamper-detection. Flipping any byte in the document body
        // changes the hash that ML-DSA-65 + Ed25519 each signed, so
        // both component verifications fail.
        documentBytes[0] ^= 0xFF;
        var tamperedOk = HybridSignature.Verify(publicKey, documentBytes, signature);
        Console.WriteLine($"[verifier] signature valid for tampered document: {tamperedOk} (expected False)");
    }
}
finally
{
    Directory.Delete(workDir, recursive: true);
}
