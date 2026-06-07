// =============================================================================
// PostQuantum.Hybrid sample: key persistence to PEM.
//
// Demonstrates the typical "generate once, reuse across processes" pattern:
//   1) Generate a hybrid key pair, save both halves to disk.
//   2) Load them back in a fresh "session," exercise them end-to-end.
//   3) Handle malformed input on load gracefully via the Try* API.
//
// Notes on storing private keys at rest:
//   • PEM is human-readable but UNENCRYPTED. Wrap the private-key file
//     in OS-level access controls (file permissions, DPAPI on Windows,
//     etc.) or a secret manager. This sample tightens Unix permissions
//     to 0o600 as a baseline.
//   • For production, prefer keeping private keys in an HSM / KMS and
//     only use this library with the keys held in a process boundary.
//   • Treat the PEM file contents the same way you treat the byte
//     array — clear or shred the buffer once loaded.
// =============================================================================

using System.Security.Cryptography;
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
    // Using-block on each pair so the key material is zeroed promptly
    // after we've serialized it. The PQH001 analyzer enforces this.
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
    // Use the Try* APIs at the trust boundary. The PEM file on disk
    // could be corrupted, truncated, swapped to a wrong-algorithm blob,
    // or just empty — TryImportPem returns false rather than throwing,
    // which lets callers respond to bad input without try/catch.
    Console.WriteLine("[runtime] reloading KEM keys and round-tripping...");
    if (!HybridKemPublicKey.TryImportPem(File.ReadAllText(kemPubFile), out var kemPub))
    {
        throw new CryptographicException($"Refusing to use {kemPubFile}: PEM parse failed.");
    }
    if (!HybridKemPrivateKey.TryImportPem(File.ReadAllText(kemPrivFile), out var kemPriv))
    {
        throw new CryptographicException($"Refusing to use {kemPrivFile}: PEM parse failed.");
    }
    using (kemPriv)
    using (var enc = HybridKem.Encapsulate(kemPub))
    {
        var recovered = HybridKem.Decapsulate(kemPriv, enc.Ciphertext);
        var match = CryptographicOperations.FixedTimeEquals(enc.Secret.AsSpan(), recovered);
        Console.WriteLine($"[runtime] KEM round-trip: {(match ? "OK" : "FAIL")}");
        CryptographicOperations.ZeroMemory(recovered);
    }

    Console.WriteLine("[runtime] reloading signature keys and round-tripping...");
    if (!HybridSignaturePublicKey.TryImportPem(File.ReadAllText(sigPubFile), out var sigPub))
    {
        throw new CryptographicException($"Refusing to use {sigPubFile}: PEM parse failed.");
    }
    if (!HybridSignaturePrivateKey.TryImportPem(File.ReadAllText(sigPrivFile), out var sigPriv))
    {
        throw new CryptographicException($"Refusing to use {sigPrivFile}: PEM parse failed.");
    }
    using (sigPriv)
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

    // ----- Show graceful handling of a corrupted blob. -----
    Console.WriteLine();
    Console.WriteLine("[demo] simulating a corrupted KEM public PEM...");
    var corrupted = "-----BEGIN PQH HYBRID KEM PUBLIC KEY-----\nGARBAGE\n-----END PQH HYBRID KEM PUBLIC KEY-----\n";
    if (!HybridKemPublicKey.TryImportPem(corrupted, out _))
    {
        Console.WriteLine("[demo] TryImportPem cleanly returned false (no throw).");
    }
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
    // On Windows, file inherits NTFS ACL from the parent. In production
    // you'd want to apply an explicit ACL granting only the current user.
}
