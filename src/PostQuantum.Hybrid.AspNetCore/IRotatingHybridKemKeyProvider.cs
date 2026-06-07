namespace PostQuantum.Hybrid.AspNetCore;

/// <summary>
/// A KEM key provider that watches its on-disk source and atomically
/// swaps in a new key pair when the file changes.
/// </summary>
/// <remarks>
/// During a swap, in-flight callers continue to use the old key pair —
/// the old <see cref="HybridKemPrivateKey"/> stays valid until the last
/// caller releases it. Subsequent reads of the <c>PublicKey</c> and
/// <c>PrivateKey</c> properties see the new pair.
/// </remarks>
public interface IRotatingHybridKemKeyProvider : IHybridKemKeyProvider, IDisposable
{
    /// <summary>The version stamp of the currently-active key pair.</summary>
    int Version { get; }

    /// <summary>
    /// Raised after a rotation completes. The <c>int</c> argument is the new
    /// <see cref="Version"/>.
    /// </summary>
    event Action<int>? Rotated;
}
