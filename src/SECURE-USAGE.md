# Secure Usage — PostQuantum.Hybrid

Prescriptive patterns for using PostQuantum.Hybrid correctly. Each
section starts with **"Do this"**, then gives the rationale.

## 1. Always wrap KEM with AEAD

**Do this:**

```csharp
using var enc = HybridKem.Encapsulate(recipientPub);
var kemCt = enc.Ciphertext.ToBytes();

var aesKey = new byte[32];
HKDF.Expand(HashAlgorithmName.SHA256, enc.SharedSecret, aesKey,
            info: Concat("MyApp v1", kemCt));

var nonce = RandomNumberGenerator.GetBytes(12);
var ct = new byte[plaintext.Length];
var tag = new byte[16];
using var aes = new AesGcm(aesKey, 16);
aes.Encrypt(nonce, plaintext, ct, tag, associatedData: kemCt);
CryptographicOperations.ZeroMemory(aesKey);
```

**Why:** A KEM produces a *secret*, not a *ciphertext*. The secret is
random and short; your plaintext is neither. You always need an AEAD on
top, and AES-GCM is the right default. Binding `kemCt` into
`associatedData` ensures an attacker can't swap KEM ciphertexts to
re-key the AEAD against a different exchange.

## 2. Always sign-then-verify before decrypt

**Do this:**

```csharp
if (!HybridSignature.Verify(senderPub, payload, signature))
{
    throw new CryptographicException("Signature failed; refusing to decrypt.");
}

var kemCt = HybridKemCiphertext.FromBytes(payload[..1121]);
var ss = HybridKem.Decapsulate(myPriv, kemCt);
// ... derive AES key, decrypt ...
```

**Why:** Decrypting unauthenticated material is the canonical way to
get owned. Padding oracles, fault attacks, and malformed-input bugs all
require the attacker to be able to feed the decryptor untrusted bytes.
Verifying the signature first shrinks the attack surface to "the
signer's private key was compromised" — the same threat model as your
authentication primitive.

## 3. Always `using` your private keys

**Do this:**

```csharp
using var pair = HybridSignature.GenerateKeyPair();
// ... use pair.PrivateKey ...
// pair.PrivateKey is zeroed here.
```

Or:

```csharp
HybridSignaturePrivateKey priv;
try
{
    priv = HybridSignaturePrivateKey.ImportPem(File.ReadAllText("signer.pem"));
    // ...
}
finally
{
    priv?.Dispose();
}
```

**Why:** The GC has no obligation to zero unused memory before
collecting it. Sensitive bytes sitting around in managed heap pages are
recoverable from crash dumps, paging files, and live-memory dumps in
shared environments. `Dispose` zeroes the buffers; without it you're
trusting GC timing for security.

## 4. Always rotate static keys

**Do this:** Decide a rotation cadence (1–2 years for long-lived
signing keys; per-session for KEM ephemerals — the library does this
for you automatically). Set an alarm. Renew before expiry.

**Why:** A long-lived key that's been used to sign millions of messages
or decap millions of ciphertexts is a more attractive target than a
fresh one. Rotation limits the blast radius of an undetected
compromise.

## 5. Never derive an AEAD key directly from `SharedSecret` without HKDF

**Don't do this:**

```csharp
// WRONG
using var aes = new AesGcm(enc.SharedSecret, 16);
```

**Do this:**

```csharp
var key = new byte[32];
HKDF.Expand(HashAlgorithmName.SHA256, enc.SharedSecret, key,
            info: "MyApp v1 AES-256-GCM key"u8);
using var aes = new AesGcm(key, 16);
```

**Why:** The KEM shared secret is uniform and 32 bytes — coincidentally
exactly what AES-256 needs. Passing it directly works *numerically* but
loses two important properties: (1) domain separation — if you derive
multiple keys from one exchange (e.g. one for encryption, one for HMAC)
HKDF gives you independent keys; using `SharedSecret` directly gives
you the same key everywhere; (2) the `info` parameter binds the key to
the *purpose* it's being derived for, preventing cross-protocol
attacks.

## 6. Always check the algorithm identifier on import

**You don't have to do anything** — the library does this for you. But
if you ever serialize a hybrid blob across systems with versioning
concerns, ensure both sides agree on the algorithm identifier before
parsing.

```csharp
var bytes = File.ReadAllBytes("recipient.pub");
if (bytes[0] != (byte)HybridKemAlgorithm.X25519MlKem768)
{
    throw new InvalidDataException($"Expected X25519MlKem768, got algorithm {bytes[0]}");
}
var pub = HybridKemPublicKey.Import(bytes);
```

## 7. Always handle decapsulation as authentication

**Why:** A `HybridKem.Decapsulate` call **always succeeds** (this is
ML-KEM's implicit-rejection design). On a malformed ciphertext, the
returned secret is pseudo-random. The combined hybrid secret then
differs from the sender's, and downstream AEAD `Decrypt` will throw
`AuthenticationTagMismatchException`. **That AEAD failure is your
authentication signal** for the KEM ciphertext, not the absence of an
exception from `Decapsulate`.

## 8. Always know which backend your runtime is using

- **net10.0** users: the library prefers the native BCL
  `System.Security.Cryptography.MLKem` / `MLDsa` implementation when
  `MLKem.IsSupported` / `MLDsa.IsSupported` are true, and otherwise
  transparently falls back to BouncyCastle. The public API and wire
  format stay the same either way.
- **net8.0** users: ML-KEM and ML-DSA come from BouncyCastle on every
  platform.
- **If you require the native .NET 10 backend** for policy,
  certification, or performance reasons, probe
  `System.Security.Cryptography.MLKem.IsSupported` and
  `System.Security.Cryptography.MLDsa.IsSupported` at startup and fail
  closed when either is false. Do not assume ".NET 10 installed"
  implies "native PQ available on this machine."
- **Your readiness check should exercise real crypto, not just inspect a
  flag.** A startup smoke test that loads keys, signs and verifies, and
  encapsulates and decapsulates tells you more than a support probe by
  itself.

## 9. Always document which algorithm your system uses

Operators must be able to answer "Are we post-quantum yet?" in plain
language. Put a line in your service's `/health` or your release notes:

```
Cryptography: PostQuantum.Hybrid 1.0.0
  - KEM:        X25519MlKem768 (algorithm id 0x01)
  - Signature:  Ed25519MlDsa65 (algorithm id 0x01)
```

This lets your security and compliance teams audit you without
crawling source.
