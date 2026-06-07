using Microsoft.Extensions.Logging;

namespace PostQuantum.Hybrid.AspNetCore;

internal sealed class RotatingHybridSignatureKeyProvider : IRotatingHybridSignatureKeyProvider
{
    private readonly string _publicKeyPath;
    private readonly string _privateKeyPath;
    private readonly ILogger? _logger;
    private readonly FileSystemWatcher _publicWatcher;
    private readonly FileSystemWatcher _privateWatcher;
    private readonly object _gate = new();

    private HybridSignaturePublicKey _publicKey;
    private HybridSignaturePrivateKey _privateKey;
    private int _version;
    private bool _disposed;

    public event Action<int>? Rotated;

    public int Version
    {
        get { lock (_gate) { return _version; } }
    }

    public HybridSignaturePublicKey PublicKey
    {
        get { lock (_gate) { ThrowIfDisposed(); return _publicKey; } }
    }

    public HybridSignaturePrivateKey PrivateKey
    {
        get { lock (_gate) { ThrowIfDisposed(); return _privateKey; } }
    }

    public RotatingHybridSignatureKeyProvider(string publicKeyPath, string privateKeyPath, ILogger? logger)
    {
        _publicKeyPath = publicKeyPath;
        _privateKeyPath = privateKeyPath;
        _logger = logger;

        (_publicKey, _privateKey) = LoadKeyPair();
        _version = 1;

        _publicWatcher = CreateWatcher(publicKeyPath);
        _privateWatcher = CreateWatcher(privateKeyPath);
    }

    private (HybridSignaturePublicKey Public, HybridSignaturePrivateKey Private) LoadKeyPair()
    {
        var pubPem = File.ReadAllText(_publicKeyPath);
        var privPem = File.ReadAllText(_privateKeyPath);
        return (HybridSignaturePublicKey.ImportPem(pubPem), HybridSignaturePrivateKey.ImportPem(privPem));
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
            Thread.Sleep(50);
            (HybridSignaturePublicKey Public, HybridSignaturePrivateKey Private) next;
            try
            {
                next = LoadKeyPair();
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "RotatingHybridSignatureKeyProvider: failed to reload, keeping current keys");
                return;
            }

            HybridSignaturePrivateKey? toDispose = null;
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
            // Delay disposal so in-flight callers (Sign / Verify) running
            // on worker threads can complete against the old reference
            // before its buffers are zeroed. See the matching comment in
            // RotatingHybridKemKeyProvider.
            ScheduleDelayedDispose(toDispose);
            _logger?.LogInformation("RotatingHybridSignatureKeyProvider: rotated to version {Version}", newVersion);
            Rotated?.Invoke(newVersion);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "RotatingHybridSignatureKeyProvider: unexpected exception in rotation");
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(RotatingHybridSignatureKeyProvider));
        }
    }

    /// <summary>
    /// How long to wait after a rotation before disposing the previous
    /// private signing key. See the matching property in
    /// <c>RotatingHybridKemKeyProvider</c> for the rationale.
    /// </summary>
    internal static TimeSpan RotationDisposeDelay { get; set; } = TimeSpan.FromSeconds(30);

    private void ScheduleDelayedDispose(HybridSignaturePrivateKey? key)
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
                _logger?.LogWarning(ex, "RotatingHybridSignatureKeyProvider: delayed dispose of previous private key threw");
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
