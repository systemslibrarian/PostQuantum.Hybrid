// =============================================================================
// In-process rotation service for the playground's #rotation section.
//
// The library ships IRotatingHybridKemKeyProvider in PostQuantum.Hybrid.AspNetCore;
// the file-backed implementation (RotatingHybridKemKeyProvider) is registered via
// AddRotatingHybridKemKeys(publicKeyPath, privateKeyPath) and watches its files
// with FileSystemWatcher. samples/KeyRotationDemo demonstrates the file flow
// end-to-end.
//
// In the playground we want rotation to be visible and user-driven, without
// adding a writable directory to the container image or fighting Blazor's
// scoped DI with FileSystemWatcher debounce timing. So the rotation section
// uses this in-process service that exposes the same surface area as the
// library interface (Version + PublicKey + PrivateKey + Rotated event) and
// generates fresh hybrid KEM key pairs on demand. The educational message —
// "envelopes sealed under version N do not open under version N+1" — is
// the same.
// =============================================================================

namespace PostQuantum.Hybrid.Samples.WebApiDemo.Services;

/// <summary>
/// Self-contained rotation provider for the playground. Mirrors the surface
/// of <see cref="PostQuantum.Hybrid.AspNetCore.IRotatingHybridKemKeyProvider"/>
/// (<see cref="Version"/>, <see cref="PublicKey"/>, <see cref="PrivateKey"/>,
/// <see cref="Rotated"/>) but rotates in process on demand.
/// </summary>
public sealed class PlaygroundRotationService : IDisposable
{
    private readonly object _gate = new();
    private HybridKemKeyPair _current;
    private int _version = 1;
    private bool _disposed;

    public PlaygroundRotationService()
    {
        _current = HybridKem.GenerateKeyPair();
    }

    /// <summary>Fires after a successful rotation. The argument is the new version.</summary>
    public event Action<int>? Rotated;

    /// <summary>Monotonic counter that advances on every successful rotation.</summary>
    public int Version
    {
        get { lock (_gate) { return _version; } }
    }

    /// <summary>Current hybrid KEM public key. Safe to call across rotations.</summary>
    public HybridKemPublicKey PublicKey
    {
        get { lock (_gate) { return _current.PublicKey; } }
    }

    /// <summary>Current hybrid KEM private key. Safe to call across rotations.</summary>
    public HybridKemPrivateKey PrivateKey
    {
        get { lock (_gate) { return _current.PrivateKey; } }
    }

    /// <summary>
    /// Generate a fresh hybrid KEM key pair, swap it in atomically, dispose the
    /// previous pair (zeroes its sensitive buffers), and fire <see cref="Rotated"/>.
    /// Returns the new version.
    /// </summary>
    public int Rotate()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var fresh = HybridKem.GenerateKeyPair();
        HybridKemKeyPair? old;
        int newVersion;
        lock (_gate)
        {
            old = _current;
            _current = fresh;
            newVersion = ++_version;
        }

        // Dispose old OUTSIDE the lock — disposal zeroes sensitive buffers, which
        // is cheap but we don't want to hold the gate during it.
        old?.Dispose();
        Rotated?.Invoke(newVersion);
        return newVersion;
    }

    public void Dispose()
    {
        if (_disposed) { return; }
        _disposed = true;
        HybridKemKeyPair? toDispose;
        lock (_gate) { toDispose = _current; _current = null!; }
        toDispose?.Dispose();
    }
}
