# PostQuantum.Hybrid.Envelopes

Opinionated, misuse-resistant message envelopes for
[PostQuantum.Hybrid](https://github.com/systemslibrarian/PostQuantum.Hybrid).

Wraps **KEM + HKDF + AES-GCM** into one call. Use this when you don't
want to wire up the symmetric layer yourself.

## Install

```bash
dotnet add package PostQuantum.Hybrid.Envelopes
```

## API

```csharp
namespace PostQuantum.Hybrid.Envelopes;

// Anonymous (encrypted-only) envelope
public static class HybridEnvelope
{
    public static byte[] Seal(HybridKemPublicKey recipientPublicKey, ReadOnlySpan<byte> plaintext);
    public static byte[] Open(HybridKemPrivateKey recipientPrivateKey, ReadOnlySpan<byte> envelope);
}

// Authenticated (signed + encrypted) envelope
public static class SignedHybridEnvelope
{
    public static byte[] Seal(
        HybridSignaturePrivateKey senderSigningKey,
        HybridKemPublicKey        recipientPublicKey,
        ReadOnlySpan<byte>        plaintext);

    public static byte[] Open(
        HybridSignaturePublicKey  senderVerificationKey,
        HybridKemPrivateKey       recipientPrivateKey,
        ReadOnlySpan<byte>        envelope);
}
```

## Quick start

```csharp
using PostQuantum.Hybrid;
using PostQuantum.Hybrid.Envelopes;

// Anonymous encrypted envelope
using var recipient = HybridKem.GenerateKeyPair();
byte[] envelope = HybridEnvelope.Seal(recipient.PublicKey, "secret message"u8);
byte[] plaintext = HybridEnvelope.Open(recipient.PrivateKey, envelope);

// Signed + encrypted envelope
using var sender = HybridSignature.GenerateKeyPair();
byte[] authEnv = SignedHybridEnvelope.Seal(
    sender.PrivateKey, recipient.PublicKey, "from alice"u8);
byte[] verified = SignedHybridEnvelope.Open(
    sender.PublicKey, recipient.PrivateKey, authEnv);
```

## What's inside the envelope

### Anonymous `HybridEnvelope`

```
[ 1B version ] [ 1121B KEM ciphertext ] [ 12B nonce ] [ 16B AES-GCM tag ]
[ N bytes encrypted plaintext ]
```

- `version` is `0x01` (the only version in v1; future variants get a
  new value).
- The KEM ciphertext is bound into the AEAD as `associatedData`, so
  any rearrangement breaks the tag check.
- A fresh HKDF-derived AES-256 key per call.

### Signed `SignedHybridEnvelope`

```
[ anonymous envelope above ] [ 3374B hybrid signature ]
```

- The signature is over the *entire* anonymous envelope (so the
  signature binds the encrypted payload, the KEM ciphertext, the
  nonce, and the AEAD tag).
- `Open` verifies the signature BEFORE running KEM decapsulation.
  Tampered envelopes are rejected without ever touching the
  recipient's private key.

## Failure modes

`Open` throws `CryptographicException` (specifically
`PostQuantum.Hybrid.PostQuantumHybridException` for structural problems
and `AuthenticationTagMismatchException` for AEAD failures). Match on
the base type if you need broad catching; match on
`PostQuantumHybridException.Reason` for structured handling.

## Security guarantees

| Property | Anonymous | Signed |
|---|---|---|
| Confidentiality | ✅ both X25519 and ML-KEM-768 secure → secret stays secret | ✅ |
| Integrity of payload | ✅ AES-GCM tag | ✅ AES-GCM tag + hybrid signature |
| Sender authentication | ❌ anyone could have sealed it | ✅ both Ed25519 and ML-DSA-65 secure → only sender could have sealed |
| Replay protection | ❌ caller's responsibility | ❌ caller's responsibility |
| Forward secrecy | ❌ if recipient key leaks, past envelopes decrypt | ❌ same |

For replay protection or forward secrecy, layer a protocol on top.
