namespace PostQuantum.Hybrid.AspNetCore;

/// <summary>
/// Provides the application's long-lived hybrid KEM key pair. Resolve
/// via dependency injection.
/// </summary>
public interface IHybridKemKeyProvider
{
    /// <summary>The recipient-shareable public key.</summary>
    HybridKemPublicKey PublicKey { get; }

    /// <summary>
    /// The decapsulation key. Never serialize, log, or expose this. The
    /// underlying buffers are zeroed on host shutdown.
    /// </summary>
    HybridKemPrivateKey PrivateKey { get; }
}
