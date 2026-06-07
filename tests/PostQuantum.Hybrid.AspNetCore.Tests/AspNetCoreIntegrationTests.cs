using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PostQuantum.Hybrid;
using PostQuantum.Hybrid.AspNetCore;
using Xunit;

namespace PostQuantum.Hybrid.AspNetCore.Tests;

public class AspNetCoreIntegrationTests
{
    [Fact]
    public void AddPostQuantumHybrid_FromInlinePem_RegistersBothProviders()
    {
        using var kem = HybridKem.GenerateKeyPair();
        using var sig = HybridSignature.GenerateKeyPair();

        var services = new ServiceCollection();
        services.AddPostQuantumHybrid(options =>
        {
            options.KemPublicKeyPem  = kem.PublicKey.ExportPem();
            options.KemPrivateKeyPem = kem.PrivateKey.ExportPem();
            options.SignaturePublicKeyPem  = sig.PublicKey.ExportPem();
            options.SignaturePrivateKeyPem = sig.PrivateKey.ExportPem();
        });

        using var sp = services.BuildServiceProvider();
        var kemProvider = sp.GetRequiredService<IHybridKemKeyProvider>();
        var sigProvider = sp.GetRequiredService<IHybridSignatureKeyProvider>();

        Assert.Equal(1217, kemProvider.PublicKey.Export().Length);
        Assert.Equal(2433, kemProvider.PrivateKey.Export().Length);
        Assert.Equal(1985, sigProvider.PublicKey.Export().Length);
        Assert.Equal(4065, sigProvider.PrivateKey.Export().Length);
    }

    [Fact]
    public void AddPostQuantumHybrid_FromFilePath_LoadsFromDisk()
    {
        using var kem = HybridKem.GenerateKeyPair();
        using var sig = HybridSignature.GenerateKeyPair();

        var dir = Path.Combine(Path.GetTempPath(), "pqh-aspnet-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        try
        {
            var kemPubPath  = Path.Combine(dir, "kem.pub.pem");
            var kemPrivPath = Path.Combine(dir, "kem.priv.pem");
            var sigPubPath  = Path.Combine(dir, "sig.pub.pem");
            var sigPrivPath = Path.Combine(dir, "sig.priv.pem");

            File.WriteAllText(kemPubPath,  kem.PublicKey.ExportPem());
            File.WriteAllText(kemPrivPath, kem.PrivateKey.ExportPem());
            File.WriteAllText(sigPubPath,  sig.PublicKey.ExportPem());
            File.WriteAllText(sigPrivPath, sig.PrivateKey.ExportPem());

            var services = new ServiceCollection();
            services.AddPostQuantumHybrid(options =>
            {
                options.KemPublicKeyPath  = kemPubPath;
                options.KemPrivateKeyPath = kemPrivPath;
                options.SignaturePublicKeyPath  = sigPubPath;
                options.SignaturePrivateKeyPath = sigPrivPath;
            });

            using var sp = services.BuildServiceProvider();
            var kemProvider = sp.GetRequiredService<IHybridKemKeyProvider>();

            // End-to-end: encapsulate, decapsulate via DI'd provider.
            using var enc = HybridKem.Encapsulate(kemProvider.PublicKey);
            var dec = HybridKem.Decapsulate(kemProvider.PrivateKey, enc.Ciphertext);
            Assert.Equal(enc.SharedSecret, dec);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void AddPostQuantumHybrid_FromConfiguration_BindsCorrectly()
    {
        using var kem = HybridKem.GenerateKeyPair();
        using var sig = HybridSignature.GenerateKeyPair();

        var memory = new Dictionary<string, string?>
        {
            ["Crypto:KemPublicKeyPem"]        = kem.PublicKey.ExportPem(),
            ["Crypto:KemPrivateKeyPem"]       = kem.PrivateKey.ExportPem(),
            ["Crypto:SignaturePublicKeyPem"]  = sig.PublicKey.ExportPem(),
            ["Crypto:SignaturePrivateKeyPem"] = sig.PrivateKey.ExportPem(),
        };
        var config = new ConfigurationBuilder().AddInMemoryCollection(memory).Build();

        var services = new ServiceCollection();
        services.AddPostQuantumHybrid(config.GetSection("Crypto"));

        using var sp = services.BuildServiceProvider();
        var sigProvider = sp.GetRequiredService<IHybridSignatureKeyProvider>();

        var message = "DI test"u8.ToArray();
        var sigBytes = HybridSignature.Sign(sigProvider.PrivateKey, message);
        Assert.True(HybridSignature.Verify(sigProvider.PublicKey, message, sigBytes));
    }

    [Fact]
    public void AddPostQuantumHybrid_MissingKemConfig_ThrowsOnFirstUse()
    {
        var services = new ServiceCollection();
        services.AddPostQuantumHybrid(_ => { /* nothing configured */ });
        using var sp = services.BuildServiceProvider();

        Assert.Throws<InvalidOperationException>(() => sp.GetRequiredService<IHybridKemKeyProvider>());
    }

    [Fact]
    public void AddPostQuantumHybrid_NonexistentKeyFile_ThrowsOnFirstUse()
    {
        var services = new ServiceCollection();
        services.AddPostQuantumHybrid(options =>
        {
            options.KemPublicKeyPath  = "/does/not/exist.pub.pem";
            options.KemPrivateKeyPath = "/does/not/exist.priv.pem";
            options.SignaturePublicKeyPath  = "/does/not/exist.sig.pub.pem";
            options.SignaturePrivateKeyPath = "/does/not/exist.sig.priv.pem";
        });
        using var sp = services.BuildServiceProvider();

        Assert.Throws<InvalidOperationException>(() => sp.GetRequiredService<IHybridKemKeyProvider>());
    }

    [Fact]
    public void Providers_AreSingletons()
    {
        using var kem = HybridKem.GenerateKeyPair();
        using var sig = HybridSignature.GenerateKeyPair();

        var services = new ServiceCollection();
        services.AddPostQuantumHybrid(options =>
        {
            options.KemPublicKeyPem  = kem.PublicKey.ExportPem();
            options.KemPrivateKeyPem = kem.PrivateKey.ExportPem();
            options.SignaturePublicKeyPem  = sig.PublicKey.ExportPem();
            options.SignaturePrivateKeyPem = sig.PrivateKey.ExportPem();
        });

        using var sp = services.BuildServiceProvider();
        var a = sp.GetRequiredService<IHybridKemKeyProvider>();
        var b = sp.GetRequiredService<IHybridKemKeyProvider>();
        Assert.Same(a, b);
    }
}
