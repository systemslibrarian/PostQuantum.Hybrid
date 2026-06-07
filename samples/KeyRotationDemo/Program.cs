// =============================================================================
// PostQuantum.Hybrid sample: zero-downtime KEM key rotation.
//
// Wires the rotating key provider that ships in
// PostQuantum.Hybrid.AspNetCore. The provider watches a directory on
// disk and hot-swaps its in-memory keys whenever the files change. To
// prove that this works without restarting the host, a hosted service
// (`SimulatedSidecarService`) periodically overwrites the PEM files on
// disk — exactly as a real KMS sidecar or rotation cron job would.
//
// Endpoints:
//   GET  /key             — current public key (PEM) + provider Version
//   GET  /health          — liveness probe
//   POST /seal            — encrypt body against the *current* public key
//   POST /open            — decrypt body with the *current* private key
//
// What to look for when you run this:
//   1. Hit GET /key repeatedly. Every ~15 seconds the "version" field
//      advances and the PEM body changes — without a restart.
//   2. POST /seal a string; the response is base64(envelope). If you
//      take that envelope to POST /open *before* the next rotation,
//      the decryption succeeds. Wait through a rotation, then send the
//      same envelope: it fails to open because the private key has
//      changed. That is what zero-downtime rotation looks like — and
//      why your application protocol probably wants to expire
//      ciphertexts deliberately rather than relying on key lifetime.
//
// =============================================================================

using System.Text;
using Microsoft.AspNetCore.Mvc;
using PostQuantum.Hybrid;
using PostQuantum.Hybrid.AspNetCore;
using PostQuantum.Hybrid.Envelopes;

var builder = WebApplication.CreateBuilder(args);

// The directory the simulator will write PEM files into and the provider
// will watch. In production this is wherever your KMS sidecar drops
// rotated keys. We put it in the OS temp dir so the .NET hot-reload
// watchers in the build output don't fight the rotation watcher.
var keysDir = Path.Combine(Path.GetTempPath(), "pqh-key-rotation-demo");
Directory.CreateDirectory(keysDir);
var publicKeyPath  = Path.Combine(keysDir, "kem.pub.pem");
var privateKeyPath = Path.Combine(keysDir, "kem.priv.pem");
Console.WriteLine($"[startup] keys directory: {keysDir}");

// Bootstrap: write an initial pair so the provider has something to load
// at startup. Without this, RotatingHybridKemKeyProvider would throw
// FileNotFoundException on the first request.
WriteFreshKeyPair(publicKeyPath, privateKeyPath);

// Register the rotating provider. Behind the scenes it uses
// FileSystemWatcher with debounce + atomic-rename safety; we just give
// it the two paths.
builder.Services.AddRotatingHybridKemKeys(publicKeyPath, privateKeyPath);

// Stand up the sidecar simulator. Every 15 seconds it overwrites the
// PEM files. In production this would be your actual KMS, Kubernetes
// secret sync, AWS Secrets Manager rotation, etc. — the application
// code does not change.
builder.Services.AddSingleton(new RotatorOptions(publicKeyPath, privateKeyPath, TimeSpan.FromSeconds(15)));
builder.Services.AddHostedService<SimulatedSidecarService>();

var app = builder.Build();

// Surface the provider's Rotated event in the log so it's obvious the
// hot swap is happening (and easy to spot when it is NOT).
var rotProvider = app.Services.GetRequiredService<IRotatingHybridKemKeyProvider>();
var rotLogger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("KeyRotationDemo");
rotProvider.Rotated += v => rotLogger.LogInformation("Provider rotated to version {Version}.", v);

app.MapGet("/", () => Results.Text(
    "PostQuantum.Hybrid KeyRotationDemo. See GET /key, POST /seal, POST /open, POST /rotate."));

// Backup verification path: explicitly trigger a write to disk and wait
// briefly for the FileSystemWatcher to react. Useful for confirming
// the rotation path end-to-end without waiting on the 15s sidecar
// cycle.
app.MapPost("/rotate", async (IRotatingHybridKemKeyProvider keys) =>
{
    var before = keys.Version;
    var tcs = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
    void Handler(int v)
    {
        if (v > before)
        {
            tcs.TrySetResult(v);
        }
    }
    keys.Rotated += Handler;
    try
    {
        WriteFreshKeyPair(publicKeyPath, privateKeyPath);
        var winner = await Task.WhenAny(tcs.Task, Task.Delay(TimeSpan.FromSeconds(5)));
        if (winner == tcs.Task)
        {
            return Results.Json(new { rotatedFromVersion = before, rotatedToVersion = await tcs.Task });
        }
        return Results.Json(new
        {
            warning = "rotation event not received within 5s — watcher may be delayed on this host.",
            currentVersion = keys.Version,
        });
    }
    finally
    {
        keys.Rotated -= Handler;
    }
});

app.MapGet("/health", () => Results.Text("ok"));

app.MapGet("/key", (IRotatingHybridKemKeyProvider keys) =>
{
    // Snapshot version and PEM together so we don't accidentally
    // report a version with the wrong key body.
    var version = keys.Version;
    var pem = keys.PublicKey.ExportPem();
    return Results.Json(new
    {
        version,
        publicKeyPem = pem,
    });
});

app.MapPost("/seal", ([FromBody] SealRequest req, IHybridKemKeyProvider keys) =>
{
    if (req?.Plaintext is null)
    {
        return Results.BadRequest("missing 'plaintext'.");
    }

    // One call. No HKDF, no AesGcm, no nonce management — the Envelopes
    // package handles the AEAD pipeline with the safe defaults.
    var envelope = HybridEnvelope.Seal(keys.PublicKey, Encoding.UTF8.GetBytes(req.Plaintext));
    return Results.Json(new SealResponse(Convert.ToBase64String(envelope)));
});

app.MapPost("/open", ([FromBody] OpenRequest req, IRotatingHybridKemKeyProvider keys) =>
{
    if (req?.Envelope is null)
    {
        return Results.BadRequest("missing 'envelope'.");
    }
    if (!TryDecodeBase64(req.Envelope, out var envelope))
    {
        return Results.BadRequest("'envelope' is not valid base64.");
    }

    // The current private key resolves through the same provider as the
    // public key on the seal side. The IRotatingHybridKemKeyProvider
    // surface lets us also surface `keys.Version` for diagnostics.
    try
    {
        var plaintext = HybridEnvelope.Open(keys.PrivateKey, envelope);
        return Results.Json(new OpenResponse(
            Plaintext: Encoding.UTF8.GetString(plaintext),
            DecryptedWithKeyVersion: keys.Version));
    }
    catch (System.Security.Cryptography.CryptographicException)
    {
        // Most common reason here in this sample: the envelope was
        // sealed against a previous key version that has since been
        // rotated out. Show the current version so the caller can
        // see the gap.
        return Results.Json(new
        {
            error = "envelope failed to open (likely sealed against a rotated-out key).",
            currentKeyVersion = keys.Version,
        }, statusCode: 410); // 410 Gone
    }
});

app.Run();

static void WriteFreshKeyPair(string publicKeyPath, string privateKeyPath)
{
    using var pair = HybridKem.GenerateKeyPair();

    // Write the private half FIRST. The rotating provider's watcher
    // reloads both halves together, so when the public-key change
    // event fires we want the private half to already be the new one.
    // Writing the public file second is therefore the rotation trigger.
    File.WriteAllText(privateKeyPath, pair.PrivateKey.ExportPem());
    File.WriteAllText(publicKeyPath, pair.PublicKey.ExportPem());

    if (!OperatingSystem.IsWindows())
    {
        File.SetUnixFileMode(privateKeyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
}

static bool TryDecodeBase64(string value, out byte[] decoded)
{
    try { decoded = Convert.FromBase64String(value); return true; }
    catch (FormatException) { decoded = Array.Empty<byte>(); return false; }
}

record SealRequest(string Plaintext);
record SealResponse(string Envelope);
record OpenRequest(string Envelope);
record OpenResponse(string Plaintext, int DecryptedWithKeyVersion);

record RotatorOptions(string PublicKeyPath, string PrivateKeyPath, TimeSpan Interval);

/// <summary>
/// Hosted service that rotates the on-disk keys on a fixed interval.
/// In a real deployment this is a KMS sidecar, a Kubernetes secret
/// reconciler, or a scheduled job — the application code wiring is
/// identical.
/// </summary>
sealed class SimulatedSidecarService : Microsoft.Extensions.Hosting.BackgroundService
{
    private readonly RotatorOptions _options;
    private readonly ILogger<SimulatedSidecarService> _logger;

    public SimulatedSidecarService(RotatorOptions options, ILogger<SimulatedSidecarService> logger)
    {
        _options = options;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(_options.Interval, stoppingToken);
                WriteFreshKeyPair(_options.PublicKeyPath, _options.PrivateKeyPath);
                _logger.LogInformation("Sidecar rotated keys on disk at {Time}.", DateTimeOffset.UtcNow);
            }
            catch (TaskCanceledException) { /* shutdown */ }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Sidecar key rotation failed.");
            }
        }
    }

    private static void WriteFreshKeyPair(string publicKeyPath, string privateKeyPath)
    {
        using var pair = HybridKem.GenerateKeyPair();
        var tmpPub  = publicKeyPath + ".tmp";
        var tmpPriv = privateKeyPath + ".tmp";
        File.WriteAllText(tmpPub, pair.PublicKey.ExportPem());
        File.WriteAllText(tmpPriv, pair.PrivateKey.ExportPem());
        File.Move(tmpPriv, privateKeyPath, overwrite: true);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(privateKeyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        File.Move(tmpPub, publicKeyPath, overwrite: true);
    }
}
