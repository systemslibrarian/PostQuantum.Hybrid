using Microsoft.Extensions.Logging;

namespace PostQuantum.Hybrid.AspNetCore;

internal static class KeyProviderFactory
{
    public static IHybridKemKeyProvider CreateKem(HybridCryptoOptions options, ILogger? logger)
    {
        var pubPem = ResolvePem(
            inline: options.KemPublicKeyPem,
            path: options.KemPublicKeyPath,
            kind: "KEM public",
            logger: logger);
        var privPem = ResolvePem(
            inline: options.KemPrivateKeyPem,
            path: options.KemPrivateKeyPath,
            kind: "KEM private",
            logger: logger);

        var publicKey = HybridKemPublicKey.ImportPem(pubPem);
        var privateKey = HybridKemPrivateKey.ImportPem(privPem);
        return new HybridKemKeyProviderImpl(publicKey, privateKey);
    }

    public static IHybridSignatureKeyProvider CreateSignature(HybridCryptoOptions options, ILogger? logger)
    {
        var pubPem = ResolvePem(
            inline: options.SignaturePublicKeyPem,
            path: options.SignaturePublicKeyPath,
            kind: "signature public",
            logger: logger);
        var privPem = ResolvePem(
            inline: options.SignaturePrivateKeyPem,
            path: options.SignaturePrivateKeyPath,
            kind: "signature private",
            logger: logger);

        var publicKey = HybridSignaturePublicKey.ImportPem(pubPem);
        var privateKey = HybridSignaturePrivateKey.ImportPem(privPem);
        return new HybridSignatureKeyProviderImpl(publicKey, privateKey);
    }

    private static string ResolvePem(string? inline, string? path, string kind, ILogger? logger)
    {
        if (!string.IsNullOrWhiteSpace(inline))
        {
            return inline!;
        }
        if (!string.IsNullOrWhiteSpace(path))
        {
            if (!File.Exists(path))
            {
                throw new InvalidOperationException(
                    $"PostQuantum.Hybrid {kind} key file not found: {path}");
            }
            logger?.LogInformation("Loaded PostQuantum.Hybrid {Kind} key from {Path}", kind, path);
            return File.ReadAllText(path);
        }
        throw new InvalidOperationException(
            $"PostQuantum.Hybrid {kind} key not configured. Provide either the inline PEM or a file path.");
    }
}

internal sealed class HybridKemKeyProviderImpl : IHybridKemKeyProvider, IDisposable
{
    public HybridKemPublicKey PublicKey { get; }
    public HybridKemPrivateKey PrivateKey { get; }

    public HybridKemKeyProviderImpl(HybridKemPublicKey publicKey, HybridKemPrivateKey privateKey)
    {
        PublicKey = publicKey;
        PrivateKey = privateKey;
    }

    public void Dispose() => PrivateKey.Dispose();
}

internal sealed class HybridSignatureKeyProviderImpl : IHybridSignatureKeyProvider, IDisposable
{
    public HybridSignaturePublicKey PublicKey { get; }
    public HybridSignaturePrivateKey PrivateKey { get; }

    public HybridSignatureKeyProviderImpl(HybridSignaturePublicKey publicKey, HybridSignaturePrivateKey privateKey)
    {
        PublicKey = publicKey;
        PrivateKey = privateKey;
    }

    public void Dispose() => PrivateKey.Dispose();
}
