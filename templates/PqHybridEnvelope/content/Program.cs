// =============================================================================
// PostQuantum.Hybrid envelope CLI starter.
//
// Usage:
//   pqhybrid-envelope generate-keys <prefix>
//   pqhybrid-envelope seal   <recipient.pub.pem> <input-file>  <output.env>
//   pqhybrid-envelope open   <recipient.priv.pem> <input.env>  <output-file>
//
// Demonstrates the canonical HybridEnvelope use case: encrypted-at-rest
// blobs with hybrid post-quantum confidentiality.
// =============================================================================

using PostQuantum.Hybrid;
using PostQuantum.Hybrid.Envelopes;

if (args.Length == 0)
{
    Console.Error.WriteLine(
        "usage:\n" +
        "  pqhybrid-envelope generate-keys <prefix>\n" +
        "  pqhybrid-envelope seal   <recipient.pub.pem> <input-file>  <output.env>\n" +
        "  pqhybrid-envelope open   <recipient.priv.pem> <input.env>  <output-file>");
    return 1;
}

return args[0] switch
{
    "generate-keys" when args.Length == 2 => GenerateKeys(args[1]),
    "seal"          when args.Length == 4 => Seal(args[1], args[2], args[3]),
    "open"          when args.Length == 4 => Open(args[1], args[2], args[3]),
    _ => Usage(),
};

static int Usage()
{
    Console.Error.WriteLine("Bad arguments. Run with no arguments for usage.");
    return 1;
}

static int GenerateKeys(string prefix)
{
    using var pair = HybridKem.GenerateKeyPair();
    File.WriteAllText(prefix + ".pub.pem",  pair.PublicKey.ExportPem());
    File.WriteAllText(prefix + ".priv.pem", pair.PrivateKey.ExportPem());
    if (!OperatingSystem.IsWindows())
    {
        File.SetUnixFileMode(prefix + ".priv.pem", UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
    Console.WriteLine($"Wrote {prefix}.pub.pem and {prefix}.priv.pem");
    return 0;
}

static int Seal(string pubKeyPath, string inputPath, string outputPath)
{
    var pub = HybridKemPublicKey.ImportPem(File.ReadAllText(pubKeyPath));
    var plaintext = File.ReadAllBytes(inputPath);
    var envelope = HybridEnvelope.Seal(pub, plaintext);
    File.WriteAllBytes(outputPath, envelope);
    Console.WriteLine($"Sealed {plaintext.Length} bytes -> {envelope.Length} bytes envelope.");
    return 0;
}

static int Open(string privKeyPath, string inputPath, string outputPath)
{
    using var priv = HybridKemPrivateKey.ImportPem(File.ReadAllText(privKeyPath));
    var envelope = File.ReadAllBytes(inputPath);
    var plaintext = HybridEnvelope.Open(priv, envelope);
    File.WriteAllBytes(outputPath, plaintext);
    Console.WriteLine($"Opened {envelope.Length}-byte envelope -> {plaintext.Length} bytes.");
    return 0;
}
