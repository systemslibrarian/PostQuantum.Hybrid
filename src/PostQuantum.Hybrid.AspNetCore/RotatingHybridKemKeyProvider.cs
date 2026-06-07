using Microsoft.Extensions.Logging;

namespace PostQuantum.Hybrid.AspNetCore;

internal sealed class RotatingHybridKemKeyProvider : IRotatingHybridKemKeyProvider
{
    private readonly string _publicKeyPath;
    private readonly string _privateKeyPath;
    private readonly ILogger? _logger;
    private readonly FileSystemWatcher _publicWatcher;
    private readonly FileSystemWatcher _privateWatcher;
    private readonly object _gate = new();

    private HybridKemPublicKey _publicKey;
    private HybridKemPrivateKey _privateKey;
    private int _version;
    private bool _disposed;

    public event Action<int>? Rotated;

    public int Version
    {
        get { lock (_gate) { return _version; } }
    }

    public HybridKemPublicKey PublicKey
    {
        get { lock (_gate) { ThrowIfDisposed(); return _publicKey; } }
    }

    public HybridKemPrivateKey PrivateKey
    {
        get { lock (_gate) { ThrowIfDisposed(); return _privateKey; } }
    }

    public RotatingHybridKemKeyProvider(string publicKeyPath, string privateKeyPath, ILogger? logger)
    {
        _publicKeyPath = publicKeyPath;
        _privateKeyPath = privateKeyPath;
        _logger = logger;

        (_publicKey, _privateKey) = LoadKeyPair();
        _version = 1;

        _publicWatcher = CreateWatcher(publicKeyPath);
        _privateWatcher = CreateWatcher(privateKeyPath);
    }

    private (HybridKemPublicKey Public, HybridKemPrivateKey Private) LoadKeyPair()
    {
        var pubPem = File.ReadAllText(_publicKeyPath);
        var privPem = File.ReadAllText(_privateKeyPath);
        return (HybridKemPublicKey.ImportPem(pubPem), HybridKemPrivateKey.ImportPem(privPem));
    }

    private FileSystemWatcher CreateWatcher(string path)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(path))!;
        var file = Path.GetFileName(path);
        var watcher = new FileSystemWatcher(dir, file)
        {
            NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime,
            EnableRaisingEvents = true,
        };
        watcher.Changed += OnFileChanged;
        watcher.Created += OnFileChanged;
        return watcher;
    }

    private void OnFileChanged(object sender, FileSystemEventArgs e)
    {
        try
        {
            // Brief debounce so we don't tear during atomic rename + truncate.
            Thread.Sleep(50);
            (HybridKemPublicKey Public, HybridKemPrivateKey Private) next;
            try
            {
                next = LoadKeyPair();
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "RotatingHybridKemKeyProvider: failed to reload, keeping current keys");
                return;
            }

            HybridKemPrivateKey? toDispose = null;
            int newVersion;
            lock (_gate)
            {
                if (_disposed)
                {
                    next.Private.Dispose();
                    return;
                }
                toDispose = _privateKey;
                _publicKey = next.Public;
                _privateKey = next.Private;
                newVersion = ++_version;
            }
            // Delay disposal of the rotated-out private key so in-flight
            // callers that fetched .PrivateKey before the swap can complete
            // their decapsulation. Without this delay, an active
            // HybridKem.Decapsulate(...) running on a worker thread can race
            // the dispose and observe a zeroed buffer / ObjectDisposedException
            // mid-operation. The window is bounded by RotationDisposeDelay;
            // 30 s is generous for typical request lifetimes and short enough
            // that an attacker who steals an in-RAM key copy still loses it
            // within the next rotation cycle.
            ScheduleDelayedDispose(toDispose);
            _logger?.LogInformation("RotatingHybridKemKeyProvider: rotated to version {Version}", newVersion);
            Rotated?.Invoke(newVersion);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "RotatingHybridKemKeyProvider: unexpected exception in rotation");
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(RotatingHybridKemKeyProvider));
        }
    }

    /// <summary>
    /// How long to wait after a rotation before disposing the
    /// previous private-key instance. Long enough for in-flight
    /// callers that grabbed the old reference to finish; short enough
    /// that a stolen in-RAM copy doesn't outlive the next rotation by
    /// much. Internal to make this tunable for tests if it ever needs
    /// to be.
    /// </summary>
    internal static TimeSpan RotationDisposeDelay { get; set; } = TimeSpan.FromSeconds(30);

    private void ScheduleDelayedDispose(HybridKemPrivateKey? key)
    {
        if (key is null) { return; }
        var delay = RotationDisposeDelay;
        _ = Task.Run(async () =>
        {
            try
            {
                if (delay > TimeSpan.Zero)
                {
                    await Task.Delay(delay).ConfigureAwait(false);
                }
                key.Dispose();
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "RotatingHybridKemKeyProvider: delayed dispose of previous private key threw");
            }
        });
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
        }
        _publicWatcher.Dispose();
        _privateWatcher.Dispose();
        _privateKey.Dispose();
    }
}
