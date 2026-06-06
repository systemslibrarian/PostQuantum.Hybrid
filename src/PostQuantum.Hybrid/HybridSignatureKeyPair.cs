namespace PostQuantum.Hybrid;

/// <summary>
/// A matched hybrid signature public/private key pair. Disposing the pair
/// disposes the private key.
/// </summary>
public sealed class HybridSignatureKeyPair : IDisposable
{
    /// <summary>The signature-verification (public) key.</summary>
    public HybridSignaturePublicKey PublicKey { get; }

    /// <summary>The signature-generation (private) key. Dispose when done.</summary>
    public HybridSignaturePrivateKey PrivateKey { get; }

    /// <summary>The algorithm combination this key pair was generated for.</summary>
    public HybridSignatureAlgorithm Algorithm => PublicKey.Algorithm;

    internal HybridSignatureKeyPair(HybridSignaturePublicKey publicKey, HybridSignaturePrivateKey privateKey)
    {
        PublicKey = publicKey;
        PrivateKey = privateKey;
    }

    /// <summary>Disposes the underlying private key.</summary>
    public void Dispose() => PrivateKey.Dispose();
}
