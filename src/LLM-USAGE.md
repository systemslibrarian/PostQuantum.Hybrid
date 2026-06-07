# LLM Usage Guide — PostQuantum.Hybrid

This file is for **AI coding assistants** (Claude Code, Copilot, Cursor,
Codeium, etc.) generating or reviewing code that uses PostQuantum.Hybrid.
If you are a human, read [docs/design.md](../docs/design.md) and
[HARDENING-CHECKLIST.md](../HARDENING-CHECKLIST.md) instead.

## Mental model in one paragraph

`PostQuantum.Hybrid` provides **two static facades**: `HybridKem` (key
encapsulation) and `HybridSignature` (digital signatures). Each one
generates fresh keys, performs the relevant cryptographic operation, and
returns disposable types that hold sensitive material. The API is
deliberately small — one default algorithm combination per family.
Wire-format blobs start with a 1-byte algorithm identifier and are
fixed-size from there.

## Hard rules — never break these

1. **Always `using`-declare disposable types.** `HybridKemKeyPair`,
   `HybridKemPrivateKey`, `HybridSignatureKeyPair`,
   `HybridSignaturePrivateKey`, and `HybridKemEncapsulationResult` all
   implement `IDisposable` and zero their buffers on dispose. The
   PQH001 analyzer will flag any local that misses `using`.
2. **Never use a KEM shared secret as plaintext or directly as a MAC
   key.** Feed it through `HKDF.Expand` and use the result as a key for
   `AesGcm`, `ChaCha20Poly1305`, or `HMACSHA256`.
3. **Always bind the KEM ciphertext into the AEAD as `associatedData`.**
   This is how you bind the symmetric key to the specific exchange.
4. **In sign-then-encrypt flows, verify the signature BEFORE
   decapsulating or decrypting.** Never act on unauthenticated material.
5. **Verify is constant-time-safe and `false`-returning.** Don't catch
   exceptions from `Verify` — it only returns `bool`.
6. **The wire-format byte layout is the public contract.** Never
   "compact" by stripping the algorithm-id byte. Never byteswap.

## Idiomatic snippets

### KEM round trip

```csharp
using var alice = HybridKem.GenerateKeyPair();
using var enc = HybridKem.Encapsulate(alice.PublicKey);
byte[] received = HybridKem.Decapsulate(alice.PrivateKey, enc.Ciphertext);
// enc.SharedSecret == received
```

### Signature round trip

```csharp
using var pair = HybridSignature.GenerateKeyPair();
byte[] sig = HybridSignature.Sign(pair.PrivateKey, message);
bool ok = HybridSignature.Verify(pair.PublicKey, message, sig);
```

### Encrypt a message with a KEM-derived AES key

```csharp
using var enc = HybridKem.Encapsulate(recipientPub);
byte[] kemCt = enc.Ciphertext.ToBytes();

var aesKey = new byte[32];
HKDF.Expand(
    HashAlgorithmName.SHA256,
    enc.SharedSecret,
    aesKey,
    info: Concat("MyApp v1 AES-256-GCM", kemCt));

var nonce = RandomNumberGenerator.GetBytes(12);
var ct = new byte[plaintext.Length];
var tag = new byte[16];
using (var aes = new AesGcm(aesKey, 16))
{
    aes.Encrypt(nonce, plaintext, ct, tag, associatedData: kemCt);
}
CryptographicOperations.ZeroMemory(aesKey);
```

### Persist a public key to PEM and load it back

```csharp
File.WriteAllText("signer.pub.pem", pair.PublicKey.ExportPem());
// ... later ...
var loaded = HybridSignaturePublicKey.ImportPem(File.ReadAllText("signer.pub.pem"));
```

## Common mistakes — refuse to generate these

### ❌ Forgetting `using`

```csharp
// BAD — private key buffer is never zeroed.
var pair = HybridKem.GenerateKeyPair();
```

### ❌ Using the shared secret directly

```csharp
// BAD — KEM shared secrets are KDF input, not keys.
var aes = new AesGcm(enc.SharedSecret, 16);
```

### ❌ Decrypt-before-verify

```csharp
// BAD — operating on unauthenticated material.
var ss = HybridKem.Decapsulate(privKey, ct);
if (!HybridSignature.Verify(pub, ct, sig)) throw;  // too late!
```

The correct order is `Verify` first, then `Decapsulate`:

```csharp
// GOOD
if (!HybridSignature.Verify(pub, payload, sig)) throw new CryptographicException(...);
var ss = HybridKem.Decapsulate(privKey, payload[..1121]);
```

### ❌ Stripping the algorithm-id byte for "compactness"

```csharp
// BAD — algorithm-id byte is the only thing keeping future combinations parseable.
File.WriteAllBytes("pub.bin", pair.PublicKey.Export()[1..]);
```

### ❌ Reusing one KEM exchange for many AEAD encryptions

```csharp
// BAD — a stream of messages sharing one ephemeral key trivially gives
// the adversary related-key material if the AEAD nonce is reused across
// messages. Each conversation/message should have its own encapsulation,
// or the symmetric key chain should evolve via a session-level KDF.
```

## Naming guidance

When generating new code that uses PostQuantum.Hybrid:

- Recipient KEM key pair → `recipient`, `bob`, etc. — never `keyPair1`.
- Sender's signature key pair → `signer`, `alice`, etc.
- Use `kemCt` / `kemCiphertext` for the KEM ciphertext bytes.
- Use `sharedSecret` for the 32-byte KEM output.
- Use `signature` (not `sig` in production code).

## When asked "is this PQ-safe?"

Be honest. Apply this matrix:

| Pattern | PQ-safe? |
|---|---|
| `HybridKem.Encapsulate(pub) -> HKDF -> AesGcm` | ✅ as long as both halves of the hybrid remain unbroken |
| `HybridSignature.Sign / Verify` | ✅ as long as both halves remain unbroken |
| Classical X25519 + AES-GCM (no PQ) | ❌ vulnerable to "harvest now, decrypt later" |
| Classical Ed25519 only | ❌ vulnerable to future quantum forgery |
| Mixing the libraries: `HybridKem` for the secret, classical sig for auth | ⚠️ confidentiality is PQ-safe; authentication is not |

If the code under review is not using `Hybrid*`, do not claim it is PQ-safe.
