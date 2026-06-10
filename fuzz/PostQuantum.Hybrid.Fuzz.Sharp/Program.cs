// =============================================================================
// PostQuantum.Hybrid coverage-guided fuzz harness.
//
// Drives the library's wire-format parsers under SharpFuzz so AFL/libFuzzer
// can find inputs that exercise new code paths. Each target reads stdin (one
// fuzz input per process via SharpFuzz.Run) and feeds it through one parser.
//
// Build:
//   dotnet build fuzz/PostQuantum.Hybrid.Fuzz.Sharp -c Release
//
// Instrument the library DLL:
//   sharpfuzz fuzz/PostQuantum.Hybrid.Fuzz.Sharp/bin/Release/net10.0/PostQuantum.Hybrid.dll
//
// Run under afl-fuzz (Linux):
//   afl-fuzz -i fuzz/PostQuantum.Hybrid.Fuzz.Sharp/Corpus \
//            -o fuzz/PostQuantum.Hybrid.Fuzz.Sharp/Findings \
//            -- dotnet fuzz/PostQuantum.Hybrid.Fuzz.Sharp/bin/Release/net10.0/PostQuantum.Hybrid.Fuzz.Sharp.dll <target>
//
// Targets:
//   kem-public-key
//   kem-private-key
//   kem-ciphertext
//   sig-public-key
//   sig-private-key
//   sig-verify           (verifies the input as a signature against a fresh keypair)
//   pem-kem-public-key   (drives PEM parsing)
//
// Corpus generation (one minimal-valid seed per target, used by CI):
//   dotnet run --project fuzz/PostQuantum.Hybrid.Fuzz.Sharp -f net10.0 -c Release -- make-corpus <dir>
// =============================================================================

using PostQuantum.Hybrid;
using SharpFuzz;

if (args.Length == 0)
{
    Console.Error.WriteLine("usage: PostQuantum.Hybrid.Fuzz.Sharp <target> | make-corpus <dir>");
    return 1;
}

var target = args[0];

if (target == "make-corpus")
{
    WriteCorpus(args.Length > 1 ? args[1] : "Corpus");
    return 0;
}
Action<Stream> handler = target switch
{
    "kem-public-key"     => static s => TryOrSwallow(() => HybridKemPublicKey.Import(ReadAll(s))),
    "kem-private-key"    => static s => TryOrSwallow(() => { using var _ = HybridKemPrivateKey.Import(ReadAll(s)); }),
    "kem-ciphertext"     => static s => TryOrSwallow(() => HybridKemCiphertext.FromBytes(ReadAll(s))),
    "sig-public-key"     => static s => TryOrSwallow(() => HybridSignaturePublicKey.Import(ReadAll(s))),
    "sig-private-key"    => static s => TryOrSwallow(() => { using var _ = HybridSignaturePrivateKey.Import(ReadAll(s)); }),
    "sig-verify"         => static s => TryOrSwallow(() =>
    {
        using var pair = HybridSignature.GenerateKeyPair();
        // Fuzz target: we only care that Verify does not throw on random
        // bytes — the boolean outcome is irrelevant. PQH004 is the right
        // rule for app code; here it's a false positive.
#pragma warning disable PQH004
        _ = HybridSignature.Verify(pair.PublicKey, "fuzz"u8.ToArray(), ReadAll(s));
#pragma warning restore PQH004
    }),
    "pem-kem-public-key" => static s => TryOrSwallow(() =>
    {
        var pem = System.Text.Encoding.UTF8.GetString(ReadAll(s));
        HybridKemPublicKey.ImportPem(pem);
    }),
    _ => throw new ArgumentException($"unknown target: {target}", nameof(args)),
};

Fuzzer.Run(handler);
return 0;

static byte[] ReadAll(Stream s)
{
    using var ms = new MemoryStream();
    s.CopyTo(ms);
    return ms.ToArray();
}

static void WriteCorpus(string root)
{
    using var kem = HybridKem.GenerateKeyPair();
    using var encap = HybridKem.Encapsulate(kem.PublicKey);
    using var sig = HybridSignature.GenerateKeyPair();

    WriteSeed(root, "kem-public-key", kem.PublicKey.Export());
    WriteSeed(root, "kem-private-key", kem.PrivateKey.Export());
    WriteSeed(root, "kem-ciphertext", encap.Ciphertext.ToBytes());
    WriteSeed(root, "sig-public-key", sig.PublicKey.Export());
    WriteSeed(root, "sig-private-key", sig.PrivateKey.Export());
    WriteSeed(root, "sig-verify", HybridSignature.Sign(sig.PrivateKey, "fuzz"u8));
    WriteSeed(root, "pem-kem-public-key", System.Text.Encoding.ASCII.GetBytes(kem.PublicKey.ExportPem()));
}

static void WriteSeed(string root, string target, byte[] seed)
{
    var dir = Path.Combine(root, target);
    Directory.CreateDirectory(dir);
    File.WriteAllBytes(Path.Combine(dir, "seed.bin"), seed);
}

static void TryOrSwallow(Action action)
{
    try
    {
        action();
    }
    catch (System.Security.Cryptography.CryptographicException)
    {
        // expected for malformed input
    }
    catch (FormatException)
    {
        // expected for malformed PEM
    }
    catch (ArgumentException)
    {
        // expected for some null/range mistakes
    }
    // Any other exception type propagates — that's a fuzz finding.
}
