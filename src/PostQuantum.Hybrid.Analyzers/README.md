# PostQuantum.Hybrid.Analyzers

Roslyn analyzers that detect common misuse patterns of
[PostQuantum.Hybrid](https://github.com/systemslibrarian/PostQuantum.Hybrid)
at build time.

## Install

```bash
dotnet add package PostQuantum.Hybrid.Analyzers
```

The analyzers run automatically inside the .NET build; no further wiring
is required.

## Rules

| ID | Severity | What it flags |
|---|---|---|
| **PQH001** | Warning | `HybridKemKeyPair`, `HybridKemPrivateKey`, `HybridSignatureKeyPair`, `HybridSignaturePrivateKey`, or `HybridKemEncapsulationResult` created without `using` and without an explicit `Dispose()` call before the variable goes out of scope. |
| **PQH002** | Warning | `HybridKemEncapsulationResult.SharedSecret` passed directly as the first argument to `AesGcm`/`AesCcm`/`ChaCha20Poly1305`/`HMACSHA*` instead of being fed through `HKDF.Expand` first. |
| **PQH003** | Warning | `HybridKem.Decapsulate(...)` called earlier in a method body than `HybridSignature.Verify(...)`. Verification must precede decapsulation in sign-then-encrypt flows. |
| **PQH004** | Warning | `HybridSignature.Verify(...)` called with its bool return value discarded. Ignoring the return is equivalent to skipping signature verification. |
| **PQH005** | Warning | `AesGcm.Encrypt` / `.Decrypt` called without `associatedData` inside a method body that also calls `HybridKem.Encapsulate` / `.Decapsulate`. Bind the KEM ciphertext as `associatedData`. |

Suggestions welcome via GitHub issues.

## Auto-fixes (code-fix providers)

Every rule ships an IDE code-fix provider so the squiggly carries a
1-keystroke "Quick Actions" remedy in VS / Rider / VS Code:

| ID | Code fix |
|---|---|
| **PQH001** | Wrap the declaration in `using` |
| **PQH002** | Wrap `.SharedSecret` in `HKDF.DeriveKey(SHA256, secret, 32, salt: null, info: /* TODO */)` |
| **PQH003** | Move the verify guard statement above the `Decapsulate` call |
| **PQH004** | Wrap the call in `if (!HybridSignature.Verify(...)) throw new CryptographicException("...");` |
| **PQH005** | Add an `associatedData` argument bound to the in-scope KEM ciphertext (TODO placeholder if none found) |

## Examples

### PQH001

```csharp
// ❌ Flagged
var pair = HybridKem.GenerateKeyPair();

// ✅ OK
using var pair = HybridKem.GenerateKeyPair();
```

### PQH004

```csharp
// ❌ Flagged (ignored bool return)
HybridSignature.Verify(pub, msg, sig);

// ❌ Flagged (explicitly discarded)
_ = HybridSignature.Verify(pub, msg, sig);

// ✅ OK
if (!HybridSignature.Verify(pub, msg, sig))
{
    throw new CryptographicException("Signature failed.");
}
```

## Suppressing a warning

Use a standard pragma or `[SuppressMessage]` attribute if you have a
legitimate reason:

```csharp
#pragma warning disable PQH001
var pair = HybridKem.GenerateKeyPair();
// ... transferred to long-lived storage that disposes elsewhere
#pragma warning restore PQH001
```
