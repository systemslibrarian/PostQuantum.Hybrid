namespace PostQuantum.Hybrid.AspNetCore;

/// <summary>
/// A signature key provider that watches its on-disk source and atomically
/// swaps in a new key pair when the file changes.
/// </summary>
public interface IRotatingHybridSignatureKeyProvider : IHybridSignatureKeyProvider, IDisposable
{
    /// <summary>The version stamp of the currently-active key pair.</summary>
    int Version { get; }

    /// <summary>Raised after a rotation completes; arg is the new <see cref="Version"/>.</summary>
    event Action<int>? Rotated;
}
