# PostQuantum.Hybrid.AspNetCore

ASP.NET Core dependency-injection extensions for
[PostQuantum.Hybrid](https://github.com/systemslibrarian/PostQuantum.Hybrid).

Lets you load hybrid KEM and signature keys from configuration and
inject them into your controllers and services without writing
boilerplate.

## Install

```bash
dotnet add package PostQuantum.Hybrid.AspNetCore
```

## Quick start

```csharp
using PostQuantum.Hybrid.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddPostQuantumHybrid(builder.Configuration.GetSection("Crypto"));

var app = builder.Build();

app.MapGet("/sign", (IHybridSignatureKeyProvider keys, string message) =>
{
    var bytes = System.Text.Encoding.UTF8.GetBytes(message);
    var sig = PostQuantum.Hybrid.HybridSignature.Sign(keys.PrivateKey, bytes);
    return Convert.ToBase64String(sig);
});

app.Run();
```

### `appsettings.json`

```jsonc
{
  "Crypto": {
    // KEM key pair — both halves required.
    "KemPublicKeyPath":  "/run/secrets/hybrid-kem.pub.pem",
    "KemPrivateKeyPath": "/run/secrets/hybrid-kem.priv.pem",

    // Signature key pair — both halves required.
    "SignaturePublicKeyPath":  "/run/secrets/hybrid-sig.pub.pem",
    "SignaturePrivateKeyPath": "/run/secrets/hybrid-sig.priv.pem"
  }
}
```

Each key half accepts either inline PEM (`*KeyPem`) or a file path
(`*KeyPath`); if both are supplied, the inline PEM wins.

You can omit a family entirely if your app doesn't need it (e.g.
only-sign apps don't need KEM keys); the corresponding provider will
throw on first use rather than at startup.

## What you get

| Service | Purpose |
|---|---|
| `IHybridKemKeyProvider` | Long-lived recipient KEM key for decapsulation. |
| `IHybridSignatureKeyProvider` | Long-lived signing key + public key. |
| `HybridCryptoOptions` | Strongly-typed configuration. |

Both providers are registered as singletons. The underlying private
keys are disposed when the host shuts down.

## Security guidance

- **Never commit `KemPrivateKeyPem` / `SignaturePrivateKeyPem` to source
  control.** Use `KemPrivateKeyPath` / `SignaturePrivateKeyPath` pointing
  at a secret-managed file, or load from a real secret store
  (Azure Key Vault, AWS Secrets Manager, HashiCorp Vault).
- **Use file permissions** on the key file (`chmod 600` on Linux; a
  restricted NTFS ACL on Windows).
- **Rotate keys.** Loading the key is one-shot; rotation requires
  restarting the host. For zero-downtime rotation, implement a custom
  `IHybridKeyProvider` that watches its source.

For more, see the parent library's [SECURITY.md](https://github.com/systemslibrarian/PostQuantum.Hybrid/blob/main/SECURITY.md)
and [HARDENING-CHECKLIST.md](https://github.com/systemslibrarian/PostQuantum.Hybrid/blob/main/HARDENING-CHECKLIST.md).
