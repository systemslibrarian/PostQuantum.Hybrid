using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Xunit;

namespace PostQuantum.Hybrid.Tests;

/// <summary>
/// Runner for NIST FIPS-203 / FIPS-204 published .rsp KAT files. Gated
/// on the environment variable <c>PQH_NIST_KAT_DIR</c>: when unset
/// (the default, including most local dev runs and the standard CI
/// matrix), every test in this class returns early. When set, each
/// test loads the matching .rsp file from that directory, parses the
/// FIPS-203 (or FIPS-204) vector blocks, and asserts that BouncyCastle
/// — and, on .NET 10 where supported, the native runtime — derives
/// the exact published bytes.
/// </summary>
/// <remarks>
/// The .rsp format we parse is the line-based "<c>key = value</c>"
/// dialect NIST publishes in their <c>kat-*.rsp</c> files. Blank lines
/// separate vector blocks; lines starting with <c>#</c> are comments.
/// We accept either the modern FIPS-203 form (<c>seed</c> = 64 bytes
/// for ML-KEM, 32 bytes for ML-DSA) or the older Round-3 form
/// (<c>seed</c> + <c>z</c>/<c>d</c> kept separately) — the parser is
/// permissive about extra keys it does not recognize.
///
/// To wire this up locally:
/// <code>
/// $env:PQH_NIST_KAT_DIR = "C:\\path\\to\\nist\\kat\\dir"
/// dotnet test --filter NistKatRunner
/// </code>
/// In CI, <c>.github/workflows/nist-kats.yml</c> sets the env var
/// after downloading the official files from <c>vars.NIST_KAT_MIRROR</c>.
/// </remarks>
public class NistKatRunner
{
    private const string DirEnvVar = "PQH_NIST_KAT_DIR";

    private static string? GetKatDir() => System.Environment.GetEnvironmentVariable(DirEnvVar);

    private static IEnumerable<KatVector> LoadOrSkip(params string[] candidateFileNames)
    {
        var dir = GetKatDir();
        if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir))
        {
            return Array.Empty<KatVector>();
        }
        foreach (var candidate in candidateFileNames)
        {
            var path = Path.Combine(dir, candidate);
            if (File.Exists(path))
            {
                return NistKatParser.ParseFile(path);
            }
        }
        return Array.Empty<KatVector>();
    }

    [Fact]
    public void MlKem768_PublicKeyMatchesBouncyCastle()
    {
        var vectors = LoadOrSkip("ML-KEM-768.rsp", "kat_MLKEM_768.rsp", "PQCkemKAT_2400.rsp").ToList();
        if (vectors.Count == 0)
        {
            return; // KAT dir not configured for this run
        }

        var checkedAny = false;
        foreach (var v in vectors)
        {
            var seed = v.TryGetBytes("seed") ?? CombineSeed(v.TryGetBytes("z"), v.TryGetBytes("d"));
            var expectedPk = v.TryGetBytes("pk") ?? v.TryGetBytes("ek");
            if (seed is null || expectedPk is null)
            {
                continue;
            }
            if (seed.Length != 64)
            {
                continue; // we only accept the FIPS-203 (z||d) seed form
            }

            var priv = MLKemPrivateKeyParameters.FromSeed(MLKemParameters.ml_kem_768, seed);
            var actualPk = priv.GetPublicKey().GetEncoded();
            Assert.Equal(expectedPk, actualPk);
            checkedAny = true;
        }
        Assert.True(checkedAny, "No ML-KEM-768 KAT vectors had the (z||d)+pk shape we accept; check the .rsp file format.");
    }

    [Fact]
    public void MlDsa65_PublicKeyMatchesBouncyCastle()
    {
        var vectors = LoadOrSkip("ML-DSA-65.rsp", "kat_MLDSA_65.rsp", "PQCsignKAT_4032.rsp").ToList();
        if (vectors.Count == 0)
        {
            return;
        }

        var checkedAny = false;
        foreach (var v in vectors)
        {
            var seed = v.TryGetBytes("seed") ?? v.TryGetBytes("xi");
            var expectedPk = v.TryGetBytes("pk");
            if (seed is null || expectedPk is null || seed.Length != 32)
            {
                continue;
            }

            var priv = MLDsaPrivateKeyParameters.FromSeed(MLDsaParameters.ml_dsa_65, seed);
            var actualPk = priv.GetPublicKey().GetEncoded();
            Assert.Equal(expectedPk, actualPk);
            checkedAny = true;
        }
        Assert.True(checkedAny, "No ML-DSA-65 KAT vectors had the xi+pk shape we accept; check the .rsp file format.");
    }

#if NET10_0_OR_GREATER
    [Fact]
    public void MlKem768_PublicKeyMatchesNative_WhenSupported()
    {
        if (!System.Security.Cryptography.MLKem.IsSupported)
        {
            return;
        }
        var vectors = LoadOrSkip("ML-KEM-768.rsp", "kat_MLKEM_768.rsp", "PQCkemKAT_2400.rsp").ToList();
        if (vectors.Count == 0)
        {
            return;
        }

        foreach (var v in vectors)
        {
            var seed = v.TryGetBytes("seed") ?? CombineSeed(v.TryGetBytes("z"), v.TryGetBytes("d"));
            var expectedPk = v.TryGetBytes("pk") ?? v.TryGetBytes("ek");
            if (seed is null || expectedPk is null || seed.Length != 64)
            {
                continue;
            }

            using var native = System.Security.Cryptography.MLKem.ImportPrivateSeed(
                System.Security.Cryptography.MLKemAlgorithm.MLKem768, seed);
            var nativePk = native.ExportEncapsulationKey();
            Assert.Equal(expectedPk, nativePk);
        }
    }

    [Fact]
    public void MlDsa65_PublicKeyMatchesNative_WhenSupported()
    {
        if (!System.Security.Cryptography.MLDsa.IsSupported)
        {
            return;
        }
        var vectors = LoadOrSkip("ML-DSA-65.rsp", "kat_MLDSA_65.rsp", "PQCsignKAT_4032.rsp").ToList();
        if (vectors.Count == 0)
        {
            return;
        }

        foreach (var v in vectors)
        {
            var seed = v.TryGetBytes("seed") ?? v.TryGetBytes("xi");
            var expectedPk = v.TryGetBytes("pk");
            if (seed is null || expectedPk is null || seed.Length != 32)
            {
                continue;
            }

            using var native = System.Security.Cryptography.MLDsa.ImportMLDsaPrivateSeed(
                System.Security.Cryptography.MLDsaAlgorithm.MLDsa65, seed);
            var nativePk = native.ExportMLDsaPublicKey();
            Assert.Equal(expectedPk, nativePk);
        }
    }
#endif

    private static byte[]? CombineSeed(byte[]? z, byte[]? d)
    {
        if (z is null || d is null)
        {
            return null;
        }
        var combined = new byte[z.Length + d.Length];
        z.CopyTo(combined.AsSpan());
        d.CopyTo(combined.AsSpan(z.Length));
        return combined;
    }
}

/// <summary>One parsed vector — a flat map of lowercased key to value text.</summary>
internal sealed class KatVector
{
    private readonly Dictionary<string, string> _values = new(StringComparer.OrdinalIgnoreCase);

    public void Set(string key, string value) => _values[key] = value;

    public byte[]? TryGetBytes(string key)
    {
        if (!_values.TryGetValue(key, out var hex))
        {
            return null;
        }
        try
        {
            return Convert.FromHexString(hex);
        }
        catch (FormatException)
        {
            return null;
        }
    }
}

/// <summary>
/// Permissive parser for NIST's <c>.rsp</c> KAT file format. Blank lines
/// separate vector blocks; lines starting with <c>#</c> are comments;
/// everything else is <c>key = value</c> with the value being either
/// hex bytes or an integer.
/// </summary>
internal static class NistKatParser
{
    public static IEnumerable<KatVector> ParseFile(string path)
    {
        var current = new KatVector();
        var hasContent = false;
        foreach (var raw in File.ReadAllLines(path))
        {
            var line = raw.Trim();
            if (line.Length == 0)
            {
                if (hasContent)
                {
                    yield return current;
                    current = new KatVector();
                    hasContent = false;
                }
                continue;
            }
            if (line[0] == '#')
            {
                continue;
            }
            var eq = line.IndexOf('=');
            if (eq <= 0)
            {
                continue;
            }
            var key = line[..eq].Trim();
            var value = line[(eq + 1)..].Trim();
            current.Set(key, value);
            hasContent = true;
        }
        if (hasContent)
        {
            yield return current;
        }
    }
}
