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
| **PQH004** | Warning | `HybridSignature.Verify(...)` called with its bool return value discarded. Ignoring the return is equivalent to skipping signature verification. |

More rules planned (PQH002 shared-secret-as-key, PQH003 verify-after-decrypt
ordering, PQH005 AEAD AAD binding). Suggestions welcome via GitHub issues.

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
