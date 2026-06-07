using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace PostQuantum.Hybrid.AspNetCore;

/// <summary>
/// <c>IServiceCollection</c> extension methods for registering
/// PostQuantum.Hybrid services in an ASP.NET Core (or any
/// Microsoft.Extensions.Hosting) application.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Register hybrid KEM and signature key providers from the given
    /// configuration section. The section is bound to
    /// <see cref="HybridCryptoOptions"/>; supply the inline PEM
    /// (e.g. <c>KemPublicKeyPem</c>) or a path to a PEM file
    /// (<c>KemPublicKeyPath</c>) for each key half you intend to use.
    /// </summary>
    public static IServiceCollection AddPostQuantumHybrid(
        this IServiceCollection services,
        IConfiguration configurationSection)
    {
        services.AddOptions<HybridCryptoOptions>().Configure(options =>
        {
            configurationSection.Bind(options);
        });
        return RegisterProviders(services);
    }

    /// <summary>
    /// Register hybrid KEM and signature key providers with options
    /// configured inline.
    /// </summary>
    public static IServiceCollection AddPostQuantumHybrid(
        this IServiceCollection services,
        Action<HybridCryptoOptions> configure)
    {
        services.AddOptions<HybridCryptoOptions>().Configure(configure);
        return RegisterProviders(services);
    }

    private static IServiceCollection RegisterProviders(IServiceCollection services)
    {
        services.AddSingleton<IHybridKemKeyProvider>(sp =>
        {
            var options = sp.GetRequiredService<IOptions<HybridCryptoOptions>>().Value;
            var logger = sp.GetService<ILoggerFactory>()?.CreateLogger("PostQuantum.Hybrid.KemKeyProvider");
            return KeyProviderFactory.CreateKem(options, logger);
        });

        services.AddSingleton<IHybridSignatureKeyProvider>(sp =>
        {
            var options = sp.GetRequiredService<IOptions<HybridCryptoOptions>>().Value;
            var logger = sp.GetService<ILoggerFactory>()?.CreateLogger("PostQuantum.Hybrid.SignatureKeyProvider");
            return KeyProviderFactory.CreateSignature(options, logger);
        });

        return services;
    }

    /// <summary>
    /// Add a rotating hybrid KEM key provider that watches its on-disk
    /// PEM files and atomically swaps keys when they change. Both public-
    /// and private-key file paths must be supplied; inline PEM is not
    /// supported for rotation (the source must be reloadable).
    /// </summary>
    public static IServiceCollection AddRotatingHybridKemKeys(
        this IServiceCollection services,
        string publicKeyPath,
        string privateKeyPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(publicKeyPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(privateKeyPath);

        services.AddSingleton<IRotatingHybridKemKeyProvider>(sp =>
        {
            var logger = sp.GetService<ILoggerFactory>()?.CreateLogger("PostQuantum.Hybrid.RotatingKemKeyProvider");
            return new RotatingHybridKemKeyProvider(publicKeyPath, privateKeyPath, logger);
        });
        services.AddSingleton<IHybridKemKeyProvider>(sp => sp.GetRequiredService<IRotatingHybridKemKeyProvider>());
        return services;
    }

    /// <summary>
    /// Add a rotating hybrid signature key provider that watches its
    /// on-disk PEM files and atomically swaps keys when they change.
    /// </summary>
    public static IServiceCollection AddRotatingHybridSignatureKeys(
        this IServiceCollection services,
        string publicKeyPath,
        string privateKeyPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(publicKeyPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(privateKeyPath);

        services.AddSingleton<IRotatingHybridSignatureKeyProvider>(sp =>
        {
            var logger = sp.GetService<ILoggerFactory>()?.CreateLogger("PostQuantum.Hybrid.RotatingSignatureKeyProvider");
            return new RotatingHybridSignatureKeyProvider(publicKeyPath, privateKeyPath, logger);
        });
        services.AddSingleton<IHybridSignatureKeyProvider>(sp => sp.GetRequiredService<IRotatingHybridSignatureKeyProvider>());
        return services;
    }
}
