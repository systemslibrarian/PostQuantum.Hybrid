using Microsoft.Extensions.DependencyInjection;
using PostQuantum.Hybrid;
using PostQuantum.Hybrid.AspNetCore;
using Xunit;

namespace PostQuantum.Hybrid.AspNetCore.Tests;

public class RotatingProvidersTests
{
    [Fact]
    public void RotatingKemProvider_LoadsInitialKey()
    {
        using var pair = HybridKem.GenerateKeyPair();
        using var dir = TempDir.Create();
        var pubPath = dir.Write("kem.pub.pem", pair.PublicKey.ExportPem());
        var privPath = dir.Write("kem.priv.pem", pair.PrivateKey.ExportPem());

        var services = new ServiceCollection();
        services.AddRotatingHybridKemKeys(pubPath, privPath);
        using var sp = services.BuildServiceProvider();

        var provider = sp.GetRequiredService<IRotatingHybridKemKeyProvider>();
        Assert.Equal(1, provider.Version);
        Assert.Equal(pair.PublicKey.Export(), provider.PublicKey.Export());
    }

    [Fact]
    public async Task RotatingKemProvider_PicksUpFileChange()
    {
        using var v1 = HybridKem.GenerateKeyPair();
        using var v2 = HybridKem.GenerateKeyPair();
        using var dir = TempDir.Create();
        var pubPath = dir.Write("kem.pub.pem", v1.PublicKey.ExportPem());
        var privPath = dir.Write("kem.priv.pem", v1.PrivateKey.ExportPem());

        var services = new ServiceCollection();
        services.AddRotatingHybridKemKeys(pubPath, privPath);
        using var sp = services.BuildServiceProvider();

        var provider = sp.GetRequiredService<IRotatingHybridKemKeyProvider>();
        var rotatedTo = new TaskCompletionSource<int>();
        provider.Rotated += v => rotatedTo.TrySetResult(v);

        // Replace both files atomically.
        File.WriteAllText(pubPath, v2.PublicKey.ExportPem());
        File.WriteAllText(privPath, v2.PrivateKey.ExportPem());

        var winner = await Task.WhenAny(rotatedTo.Task, Task.Delay(TimeSpan.FromSeconds(5)));
        Assert.Equal(rotatedTo.Task, winner);
        Assert.True(provider.Version >= 2);
        Assert.Equal(v2.PublicKey.Export(), provider.PublicKey.Export());
    }

    [Fact]
    public void RotatingSignatureProvider_LoadsInitialKey()
    {
        using var pair = HybridSignature.GenerateKeyPair();
        using var dir = TempDir.Create();
        var pubPath = dir.Write("sig.pub.pem", pair.PublicKey.ExportPem());
        var privPath = dir.Write("sig.priv.pem", pair.PrivateKey.ExportPem());

        var services = new ServiceCollection();
        services.AddRotatingHybridSignatureKeys(pubPath, privPath);
        using var sp = services.BuildServiceProvider();

        var provider = sp.GetRequiredService<IRotatingHybridSignatureKeyProvider>();
        Assert.Equal(1, provider.Version);

        // Sign/verify with the loaded keys to prove they work end-to-end.
        var msg = "rotate-load"u8.ToArray();
        var sig = HybridSignature.Sign(provider.PrivateKey, msg);
        Assert.True(HybridSignature.Verify(provider.PublicKey, msg, sig));
    }

    [Fact]
    public void RotatingProvider_AlsoSatisfiesNonRotatingInterface()
    {
        using var pair = HybridKem.GenerateKeyPair();
        using var dir = TempDir.Create();
        var pubPath = dir.Write("kem.pub.pem", pair.PublicKey.ExportPem());
        var privPath = dir.Write("kem.priv.pem", pair.PrivateKey.ExportPem());

        var services = new ServiceCollection();
        services.AddRotatingHybridKemKeys(pubPath, privPath);
        using var sp = services.BuildServiceProvider();

        var rotating = sp.GetRequiredService<IRotatingHybridKemKeyProvider>();
        var basic = sp.GetRequiredService<IHybridKemKeyProvider>();
        Assert.Same(rotating, basic);
    }

    private sealed class TempDir : IDisposable
    {
        public string Path { get; }

        private TempDir(string path) { Path = path; }

        public static TempDir Create()
        {
            var p = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "pqh-rot-" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(p);
            return new TempDir(p);
        }

        public string Write(string name, string content)
        {
            var full = System.IO.Path.Combine(Path, name);
            File.WriteAllText(full, content);
            return full;
        }

        public void Dispose()
        {
            try { Directory.Delete(Path, recursive: true); } catch { /* best-effort */ }
        }
    }
}
