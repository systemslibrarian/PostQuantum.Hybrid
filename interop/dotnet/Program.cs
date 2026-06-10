// Cross-implementation interop driver, .NET side. Exercises ML-KEM-768
// and ML-DSA-65 through the same primitives the library's backends use:
// BouncyCastle everywhere, plus System.Security.Cryptography.MLKem /
// MLDsa on .NET 10 when the OS exposes them (pass --backend=native). The
// driver script in .github/workflows/interop.yml compares this tool's
// output against Go (stdlib crypto/mlkem for ML-KEM, cloudflare/circl
// mldsa65 for ML-DSA).
//
// Subcommands (all hex in/out, one value per line):
//   mlkem-pubkey <seed(64B d||z)>          -> ek
//   mlkem-encap  <ek>                      -> ct, ss
//   mlkem-decap  <seed> <ct>               -> ss
//   mldsa-pubkey <seed(32B ξ)>             -> vk
//   mldsa-sign   <seed> <msg>              -> sig
//   mldsa-verify <vk> <msg> <sig>          -> "ok" (exit 0) | exit 1
//   backend-info                           -> "bouncycastle" or "native"

using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

const int CiphertextBytes = 1088;
const int SharedSecretBytes = 32;
const int MlDsa65SignatureBytes = 3309;

var positional = args.Where(a => !a.StartsWith("--", StringComparison.Ordinal)).ToArray();
var useNative = args.Contains("--backend=native");

if (positional.Length == 0)
{
    return Die("usage: interop [--backend=native] <mlkem-pubkey|mlkem-encap|mlkem-decap|mldsa-pubkey|mldsa-sign|mldsa-verify|backend-info> args...");
}

#if !NET10_0_OR_GREATER
if (useNative)
{
    return Die("--backend=native requires the net10.0 build of this tool.");
}
#else
if (useNative && positional[0].StartsWith("mlkem", StringComparison.Ordinal) && !System.Security.Cryptography.MLKem.IsSupported)
{
    return Die("--backend=native requested but MLKem.IsSupported is false on this host.");
}
if (useNative && positional[0].StartsWith("mldsa", StringComparison.Ordinal) && !System.Security.Cryptography.MLDsa.IsSupported)
{
    return Die("--backend=native requested but MLDsa.IsSupported is false on this host.");
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

    case "mldsa-pubkey":
    {
        var seed = Hex(positional, 1);
#if NET10_0_OR_GREATER
        if (useNative)
        {
            using var dsa = System.Security.Cryptography.MLDsa.ImportMLDsaPrivateSeed(
                System.Security.Cryptography.MLDsaAlgorithm.MLDsa65, seed);
            Console.WriteLine(Convert.ToHexString(dsa.ExportMLDsaPublicKey()).ToLowerInvariant());
            return 0;
        }
#endif
        var priv = MLDsaPrivateKeyParameters.FromSeed(MLDsaParameters.ml_dsa_65, seed);
        Console.WriteLine(Convert.ToHexString(priv.GetPublicKey().GetEncoded()).ToLowerInvariant());
        return 0;
    }

    case "mldsa-sign":
    {
        var seed = Hex(positional, 1);
        var msg = Hex(positional, 2);
        var sig = new byte[MlDsa65SignatureBytes];
#if NET10_0_OR_GREATER
        if (useNative)
        {
            using var dsa = System.Security.Cryptography.MLDsa.ImportMLDsaPrivateSeed(
                System.Security.Cryptography.MLDsaAlgorithm.MLDsa65, seed);
            dsa.SignData(msg, sig, context: default);
            Console.WriteLine(Convert.ToHexString(sig).ToLowerInvariant());
            return 0;
        }
#endif
        var priv = MLDsaPrivateKeyParameters.FromSeed(MLDsaParameters.ml_dsa_65, seed);
        var signer = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: true);
        signer.Init(forSigning: true, priv);
        signer.BlockUpdate(msg);
        Console.WriteLine(Convert.ToHexString(signer.GenerateSignature()).ToLowerInvariant());
        return 0;
    }

    case "mldsa-verify":
    {
        var vk = Hex(positional, 1);
        var msg = Hex(positional, 2);
        var sig = Hex(positional, 3);
#if NET10_0_OR_GREATER
        if (useNative)
        {
            using var dsa = System.Security.Cryptography.MLDsa.ImportMLDsaPublicKey(
                System.Security.Cryptography.MLDsaAlgorithm.MLDsa65, vk);
            if (!dsa.VerifyData(msg, sig, context: default))
            {
                return Die("verify failed");
            }
            Console.WriteLine("ok");
            return 0;
        }
#endif
        var pub = MLDsaPublicKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_65, vk);
        var verifier = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: true);
        verifier.Init(forSigning: false, pub);
        verifier.BlockUpdate(msg);
        if (!verifier.VerifySignature(sig))
        {
            return Die("verify failed");
        }
        Console.WriteLine("ok");
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
