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
            toDispose?.Dispose();
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
