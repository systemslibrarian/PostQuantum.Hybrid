// =============================================================================
// PostQuantum.Hybrid sample: key persistence to PEM.
//
// Demonstrates the typical "generate once, reuse across processes" pattern:
//   1) Generate a hybrid key pair, save both halves to disk.
//   2) Load them back in a fresh "session," exercise them end-to-end.
//
// Notes on storing private keys at rest:
//   - PEM is human-readable but UNENCRYPTED. Wrap the private-key file in
//     OS-level access controls (file permissions, DPAPI on Windows, etc.)
//     or a secret manager.
//   - For production, consider keeping private keys in an HSM/KMS and only
//     using this library with the keys held in a process boundary.
// =============================================================================

using PostQuantum.Hybrid;

Console.WriteLine("PostQuantum.Hybrid sample: PEM key persistence\n");

var workDir = Path.Combine(Path.GetTempPath(), "pqh-keys-" + Guid.NewGuid().ToString("N")[..8]);
Directory.CreateDirectory(workDir);

var kemPubFile = Path.Combine(workDir, "hybrid-kem.pub.pem");
var kemPrivFile = Path.Combine(workDir, "hybrid-kem.priv.pem");
var sigPubFile = Path.Combine(workDir, "hybrid-sig.pub.pem");
var sigPrivFile = Path.Combine(workDir, "hybrid-sig.priv.pem");

try
{
    // ----- One-time setup: generate and persist. -----
    Console.WriteLine("[setup] generating hybrid KEM key pair...");
    using (var kem = HybridKem.GenerateKeyPair())
    {
        File.WriteAllText(kemPubFile, kem.PublicKey.ExportPem());
        File.WriteAllText(kemPrivFile, kem.PrivateKey.ExportPem());
        TightenFilePermissions(kemPrivFile);
    }

    Console.WriteLine("[setup] generating hybrid signature key pair...");
    using (var sig = HybridSignature.GenerateKeyPair())
    {
        File.WriteAllText(sigPubFile, sig.PublicKey.ExportPem());
        File.WriteAllText(sigPrivFile, sig.PrivateKey.ExportPem());
        TightenFilePermissions(sigPrivFile);
    }

    Console.WriteLine($"[setup] wrote keys to {workDir}\n");

    // ----- Fresh "session": reload and exercise. -----
    Console.WriteLine("[runtime] reloading KEM keys and round-tripping...");
    var kemPub = HybridKemPublicKey.ImportPem(File.ReadAllText(kemPubFile));
    using (var kemPriv = HybridKemPrivateKey.ImportPem(File.ReadAllText(kemPrivFile)))
    using (var enc = HybridKem.Encapsulate(kemPub))
    {
        var recovered = HybridKem.Decapsulate(kemPriv, enc.Ciphertext);
        Console.WriteLine($"[runtime] KEM round-trip: " +
                          (enc.SharedSecret.AsSpan().SequenceEqual(recovered) ? "OK" : "FAIL"));
    }

    Console.WriteLine("[runtime] reloading signature keys and round-tripping...");
    var sigPub = HybridSignaturePublicKey.ImportPem(File.ReadAllText(sigPubFile));
    using (var sigPriv = HybridSignaturePrivateKey.ImportPem(File.ReadAllText(sigPrivFile)))
    {
        var message = "persisted-key proof of life"u8.ToArray();
        var signature = HybridSignature.Sign(sigPriv, message);
        var ok = HybridSignature.Verify(sigPub, message, signature);
        Console.WriteLine($"[runtime] signature round-trip: " + (ok ? "OK" : "FAIL"));
    }

    Console.WriteLine();
    Console.WriteLine("First few lines of the KEM public PEM:");
    using var reader = new StringReader(File.ReadAllText(kemPubFile));
    for (var i = 0; i < 3; i++)
    {
        var line = reader.ReadLine();
        if (line is null)
        {
            break;
        }
        Console.WriteLine("  " + line);
    }
    Console.WriteLine("  ...");
}
finally
{
    Directory.Delete(workDir, recursive: true);
}

static void TightenFilePermissions(string path)
{
    if (!OperatingSystem.IsWindows())
    {
        // Best-effort: 0o600 on Unix.
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
    // On Windows, file inherits NTFS ACL from the parent. In production you'd
    // want to apply an explicit ACL granting only the current user.
}
