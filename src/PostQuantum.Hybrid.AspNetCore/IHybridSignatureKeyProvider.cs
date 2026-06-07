namespace PostQuantum.Hybrid.AspNetCore;

/// <summary>
/// Provides the application's long-lived hybrid signature key pair.
/// Resolve via dependency injection.
/// </summary>
public interface IHybridSignatureKeyProvider
{
    /// <summary>The verification (public) key — safe to publish.</summary>
    HybridSignaturePublicKey PublicKey { get; }

    /// <summary>
    /// The signing (private) key. Never serialize, log, or expose this.
    /// The underlying buffers are zeroed on host shutdown.
    /// </summary>
    HybridSignaturePrivateKey PrivateKey { get; }
}
