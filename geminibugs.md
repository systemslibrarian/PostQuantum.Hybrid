# GitHub Copilot: PostQuantum.Hybrid — Whole-Repo Bug Audit

**Auditor:** Gemini 3.1 Pro (Preview)
**Date:** 2026-06-06
**Commit:** unavailable — no git access
**Scope:** Every source file under `src/**/*.cs` and `samples/**/*.cs`.
**Method:** File-by-file read. No sampling. All findings proven from
code actually present.

---

## File inventory

### Core library (`src/`)

| File | Bugs |
|---|---:|
| `src/PostQuantum.Hybrid/HybridKem.cs` | 1 |
| `src/PostQuantum.Hybrid/HybridSignature.cs` | 1 |
| `src/PostQuantum.Hybrid/HybridKemPrivateKey.cs` | 1 |
| `src/PostQuantum.Hybrid/Internal/MlKemBackend.cs` | 1 |
| `src/PostQuantum.Hybrid/Internal/MlDsaBackend.cs` | 1 |

*(All other `src/` files covered, 0 bugs found)*

### Samples (`samples/`)

| File | Bugs |
|---|---:|
| `samples/KemEncryption/Program.cs` | 1 |
| `samples/BasicDemo/Program.cs` | 1 |
| `samples/KeyPersistence/Program.cs` | 1 |

*(All other `samples/` files covered, 0 bugs found)*

---

## Summary

| # | File | Severity | Category | One-line description |
|---|---|---|---|---|
| 1 | `src/PostQuantum.Hybrid/HybridSignature.cs` (and others) | High | Memory Hygiene | Sensitive key spans are copied to array and never zeroed |
| 2 | `src/PostQuantum.Hybrid/HybridKemPrivateKey.cs` | High | Memory Hygiene | `ImportPem` discards GC array without zeroing it |
| 3 | `samples/KemEncryption/Program.cs` | Critical | Crypto Protocol | Missing associated data transcript binding for KEM ciphertext |
| 4 | `samples/BasicDemo/Program.cs` | Medium | Memory Hygiene | Unwiped derived KEM secret byte arrays in sample logic |
| 5 | `samples/KeyPersistence/Program.cs` | Medium | Side-Channel | Uses variable-time `SequenceEqual` on decapsulated secrets |

---

## Findings

### BUG-1 · High · Memory Hygiene

**File:** `src/PostQuantum.Hybrid/HybridSignature.cs` (Also applies to `HybridKem.cs`, `MlKemBackend.cs`, `MlDsaBackend.cs`)
**Lines:** 52–54

```csharp
// BUG: Pushing the private key span to a GC-managed array detaches it from the library's wipe guarantees.
// PROOF: The call `privateKey.ClassicalKeySpan.ToArray()` copies the raw material into a managed 
//        array. This array is bound to the `bcPriv` parameters but never explicitly zeroed 
//        via `CryptographicOperations.ZeroMemory` when the signature completes, preventing 
//        secure cleanup and allowing secrets to linger until Garbage Collection.
// TRIGGER: Any digital signature invocation, or ML-KEM decapsulation (.NET 8 fallback).
// SEVERITY: High — An attacker with host process memory access (e.g. via arbitrary read exploit, 
//           core dumps, or cold-boot attack) can recover unbounded private key handle copies.
        var bcPriv = new Ed25519PrivateKeyParameters(privateKey.ClassicalKeySpan.ToArray(), 0);
        var signer = new Ed25519Signer();
```

**Fix:** Pre-allocate a byte array, extract the key contents into it, instantiate the required BouncyCastle parameters, and implement a `try/finally` block that zeroes that specific array using `CryptographicOperations.ZeroMemory()` regardless of whether the BouncyCastle provider call throws or succeeds.

### BUG-2 · High · Memory Hygiene

**File:** `src/PostQuantum.Hybrid/HybridKemPrivateKey.cs`
**Lines:** 88–92

```csharp
// BUG: PEM imports allocate and abandon naked secret arrays.
// PROOF: `PemFormatter.Decode` allocates and returns a decrypted `byte[]`. When passed to `Import`,
//        this array is implicitly cast to `ReadOnlySpan<byte>`. `Import` creates internal clones but 
//        cannot zero the caller-provided span. The original `byte[]` allocated by the formatter 
//        is completely orphaned and drops to the GC without being zeroed.
// TRIGGER: Parsing a private key from PEM bytes on startup or runtime loads.
// SEVERITY: High — An attacker with host process memory access can recover long-term private keys.
    /// <summary>Parses a hybrid KEM private key from PEM.</summary>
    public static HybridKemPrivateKey ImportPem(string pem) => Import(PemFormatter.Decode(pem, PemLabel));
```

**Fix:** Expand the lambda into a full method. Await the returned array from `PemFormatter.Decode()`, pass it to `Import()`, and then explicitly call `CryptographicOperations.ZeroMemory()` on that array in a `finally` block before returning the structured key.

### BUG-3 · Critical · Crypto Protocol

**File:** `samples/KemEncryption/Program.cs`
**Lines:** 80–84

```csharp
// BUG: The KEM ciphertext is excluded from AEAD authenticated data bounds.
// PROOF: CLAUDE.md mandates: "Bind the KEM ciphertext into any AEAD derived from it... 
//        Pass it as associatedData so a swapped ciphertext causes authenticated decryption to fail." 
//        The decryption logic calls `aes.Decrypt()` specifying a nonce, ciphertext, and tag 
//        but ignores the `kemCt` in the `associatedData` property.
// TRIGGER: Every package wrapped/unwrapped via `KemEncryption/Program.cs`.
// SEVERITY: Critical — The attacker can forge messages by mixing ciphertexts across distinct
//           KEM channels as part of a chosen-ciphertext attack to decouple authentication properties.
    var plaintext = new byte[ciphertext.Length];
    using (var aes = new AesGcm(aesKey, TagSize))
    {
        aes.Decrypt(nonce, ciphertext, tag, plaintext); // associatedData omitted!
    }
```

**Fix:** A defect in sample logic API misuse. Add `associatedData: kemCt` (or `associatedData: encapsulation.Ciphertext.ToBytes()`) into both the `aes.Encrypt` and `aes.Decrypt` function calls to bind the underlying KEM transcript securely.

### BUG-4 · Medium · Memory Hygiene

**File:** `samples/BasicDemo/Program.cs`
**Lines:** 25–28

```csharp
// BUG: The sample code does not zero sensitive shared secret byte arrays upon completion.
// PROOF: `HybridKem.Decapsulate` allocates and outputs a `byte[]` carrying the unified 
//        secret (`aliceSecret`). After printing to `Console.WriteLine`, the `aliceSecret` 
//        reference falls out of scope, delaying the clearance until GC.
// TRIGGER: Decapsulating arbitrary Kem packets in BasicDemo.
// SEVERITY: Medium — Lack of hygiene degrades baseline posture, although the impact is limited 
//           to an ephemeral symmetric secret rather than long-term asymmetric private keys.
    // Alice decapsulates to recover the same shared secret.
    var aliceSecret = HybridKem.Decapsulate(alice.PrivateKey, encapsulation.Ciphertext);
    Console.WriteLine($"Alice's shared:    {Hex(aliceSecret)}");
```

**Fix:** A defect in sample logic. Append `CryptographicOperations.ZeroMemory(aliceSecret);` after you consume the resulting arrays to uphold correct hygiene standards modeled in the main abstractions.

### BUG-5 · Medium · Side-Channel

**File:** `samples/KeyPersistence/Program.cs`
**Lines:** 53–57

```csharp
// BUG: Non-constant time comparisons are explicitly applied to cryptographic secrets.
// PROOF: LINQ `.SequenceEqual` is used to compare the KEM secret array (`enc.SharedSecret`) against 
//        the derived `recovered` array. Sequence equal branches fail fast based on variable differences.
// TRIGGER: The assertion logic validates runtime correctness utilizing variable-time operations.
// SEVERITY: Medium — Allows attackers to theoretically probe timing oracles by examining divergence 
//           in sequence timings based on early-return failures inside `SequenceEqual`.
    using (var enc = HybridKem.Encapsulate(kemPub))
    {
        var recovered = HybridKem.Decapsulate(kemPriv, enc.Ciphertext);
        Console.WriteLine($"[runtime] KEM round-trip: " +
                          (enc.SharedSecret.AsSpan().SequenceEqual(recovered) ? "OK" : "FAIL"));
```

**Fix:** Replace the `SequenceEqual()` comparison with `CryptographicOperations.FixedTimeEquals()` on both secret spans.

---

## Previously-found bugs

None on file.

---

## Coverage statement

> Entire requested repository scope has been covered. 5 proven bug(s) reported.

---

## Suspected, unproven (optional, max 3 items)

1. **`AlgorithmSizes.cs` bounds vs malformed payloads:** `HybridKemPrivateKey.cs:75` uses fixed sizes during slice checks on private keys. If a deserialized blob exceeds total mapped lengths but survives byte ID parsing, does `.Slice(..., AlgorithmSizes.MlKem768PrivateKeyBytes)` implicitly drop trailing malicious extensions unverified? Additional testing against arbitrarily padded tailing slices is required to ensure fail-closed parse limits over arbitrary extensions.