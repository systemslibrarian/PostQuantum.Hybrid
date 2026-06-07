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

More rules will be added as the library grows. Suggestions welcome via
GitHub issues.

## Suppressing a warning

Use a standard pragma or `[SuppressMessage]` attribute if you have a
legitimate reason to hold a key without `using`:

```csharp
#pragma warning disable PQH001
var pair = HybridKem.GenerateKeyPair();
// ... transferred to long-lived storage that disposes elsewhere
#pragma warning restore PQH001
```
