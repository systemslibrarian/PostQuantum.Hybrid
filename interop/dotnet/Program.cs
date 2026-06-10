// Cross-implementation interop driver, .NET side. Exercises ML-KEM-768
// through the same primitives the library's backends use: BouncyCastle
// everywhere, plus System.Security.Cryptography.MLKem on .NET 10 when the
// OS exposes it (pass --backend native). The driver script in
// .github/workflows/interop.yml compares this tool's output against the
// Go standard library implementation in interop/go.
//
// Subcommands (all hex in/out, one value per line):
//   mlkem-pubkey <seed(64B d||z)>          -> ek
//   mlkem-encap  <ek>                      -> ct, ss
//   mlkem-decap  <seed> <ct>               -> ss
//   backend-info                           -> "bouncycastle" or "native"

using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;

const int CiphertextBytes = 1088;
const int SharedSecretBytes = 32;

var positional = args.Where(a => !a.StartsWith("--", StringComparison.Ordinal)).ToArray();
var useNative = args.Contains("--backend=native");

if (positional.Length == 0)
{
    return Die("usage: interop [--backend=native] <mlkem-pubkey|mlkem-encap|mlkem-decap|backend-info> args...");
}

#if !NET10_0_OR_GREATER
if (useNative)
{
    return Die("--backend=native requires the net10.0 build of this tool.");
}
#else
if (useNative && !System.Security.Cryptography.MLKem.IsSupported)
{
    return Die("--backend=native requested but MLKem.IsSupported is false on this host.");
}
#endif

switch (positional[0])
{
    case "backend-info":
        Console.WriteLine(useNative ? "native" : "bouncycastle");
        return 0;

    case "mlkem-pubkey":
    {
        var seed = Hex(positional, 1);
#if NET10_0_OR_GREATER
        if (useNative)
        {
            using var kem = System.Security.Cryptography.MLKem.ImportPrivateSeed(
                System.Security.Cryptography.MLKemAlgorithm.MLKem768, seed);
            Console.WriteLine(Convert.ToHexString(kem.ExportEncapsulationKey()).ToLowerInvariant());
            return 0;
        }
#endif
        var priv = MLKemPrivateKeyParameters.FromSeed(MLKemParameters.ml_kem_768, seed);
        Console.WriteLine(Convert.ToHexString(priv.GetPublicKey().GetEncoded()).ToLowerInvariant());
        return 0;
    }

    case "mlkem-encap":
    {
        var ek = Hex(positional, 1);
        var ct = new byte[CiphertextBytes];
        var ss = new byte[SharedSecretBytes];
#if NET10_0_OR_GREATER
        if (useNative)
        {
            using var kem = System.Security.Cryptography.MLKem.ImportEncapsulationKey(
                System.Security.Cryptography.MLKemAlgorithm.MLKem768, ek);
            kem.Encapsulate(ct, ss);
            Console.WriteLine(Convert.ToHexString(ct).ToLowerInvariant());
            Console.WriteLine(Convert.ToHexString(ss).ToLowerInvariant());
            return 0;
        }
#endif
        var pub = MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, ek);
        var enc = new MLKemEncapsulator(MLKemParameters.ml_kem_768);
        enc.Init(pub);
        enc.Encapsulate(ct, ss);
        Console.WriteLine(Convert.ToHexString(ct).ToLowerInvariant());
        Console.WriteLine(Convert.ToHexString(ss).ToLowerInvariant());
        return 0;
    }

    case "mlkem-decap":
    {
        var seed = Hex(positional, 1);
        var ct = Hex(positional, 2);
        var ss = new byte[SharedSecretBytes];
#if NET10_0_OR_GREATER
        if (useNative)
        {
            using var kem = System.Security.Cryptography.MLKem.ImportPrivateSeed(
                System.Security.Cryptography.MLKemAlgorithm.MLKem768, seed);
            kem.Decapsulate(ct, ss);
            Console.WriteLine(Convert.ToHexString(ss).ToLowerInvariant());
            return 0;
        }
#endif
        var priv = MLKemPrivateKeyParameters.FromSeed(MLKemParameters.ml_kem_768, seed);
        var dec = new MLKemDecapsulator(MLKemParameters.ml_kem_768);
        dec.Init(priv);
        dec.Decapsulate(ct, ss);
        Console.WriteLine(Convert.ToHexString(ss).ToLowerInvariant());
        return 0;
    }

    default:
        return Die($"unknown subcommand: {positional[0]}");
}

static byte[] Hex(string[] positional, int index)
{
    if (positional.Length <= index)
    {
        Environment.Exit(Die("missing argument"));
    }
    return Convert.FromHexString(positional[index]);
}

static int Die(string message)
{
    Console.Error.WriteLine(message);
    return 1;
}
