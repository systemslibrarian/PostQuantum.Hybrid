using System.Diagnostics;

namespace PostQuantum.Hybrid;

/// <summary>
/// A matched hybrid KEM public/private key pair. Disposing the pair disposes
/// the private key.
/// </summary>
[DebuggerDisplay("HybridKemKeyPair {Algorithm} (PrivateKey REDACTED)")]
public sealed class HybridKemKeyPair : IDisposable
{
    /// <summary>The recipient-shareable public (encapsulation) key.</summary>
    public HybridKemPublicKey PublicKey { get; }

    /// <summary>The recipient-only private (decapsulation) key. Dispose when done.</summary>
    public HybridKemPrivateKey PrivateKey { get; }

    /// <summary>The algorithm combination this key pair was generated for.</summary>
    public HybridKemAlgorithm Algorithm => PublicKey.Algorithm;

    internal HybridKemKeyPair(HybridKemPublicKey publicKey, HybridKemPrivateKey privateKey)
    {
        PublicKey = publicKey;
        PrivateKey = privateKey;
    }

    /// <summary>Disposes the underlying private key.</summary>
    public void Dispose() => PrivateKey.Dispose();
}
