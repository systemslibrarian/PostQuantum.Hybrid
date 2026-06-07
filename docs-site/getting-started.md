# Getting Started

Three minutes to your first hybrid round trip.

## 1. Install

```bash
dotnet add package PostQuantum.Hybrid
dotnet add package PostQuantum.Hybrid.Envelopes      # recommended for encryption
dotnet add package PostQuantum.Hybrid.Analyzers      # build-time misuse checks
```

## 2. Hybrid KEM round trip

```csharp
using PostQuantum.Hybrid;

// Recipient generates a key pair and publishes the public half.
using var recipient = HybridKem.GenerateKeyPair();
byte[] publicKeyBytes = recipient.PublicKey.Export();

// Sender encapsulates against the recipient's public key.
var publicKey = HybridKemPublicKey.Import(publicKeyBytes);
using var encapsulation = HybridKem.Encapsulate(publicKey);

byte[] ciphertext = encapsulation.Ciphertext.ToBytes();   // send to recipient
HybridSharedSecret secret = encapsulation.Secret;          // use locally (32 bytes)

// Recipient decapsulates to recover the same shared secret.
byte[] recovered = HybridKem.Decapsulate(recipient.PrivateKey, ciphertext);
```

## 3. Hybrid signatures

```csharp
using PostQuantum.Hybrid;
using System.Security.Cryptography;

using var signer = HybridSignature.GenerateKeyPair();
byte[] message = "Hello, post-quantum world!"u8.ToArray();
byte[] signature = HybridSignature.Sign(signer.PrivateKey, message);

if (!HybridSignature.Verify(signer.PublicKey, message, signature))
{
    throw new CryptographicException("signature verification failed.");
}
```

## 4. The recommended path for encryption

Reach for `PostQuantum.Hybrid.Envelopes` first — it collapses the
entire KEM → HKDF → AES-GCM pipeline into one method call per
direction, with all of the safety properties baked in:

```csharp
using PostQuantum.Hybrid;
using PostQuantum.Hybrid.Envelopes;
using System.Text;

using var recipient = HybridKem.GenerateKeyPair();
var plaintext = Encoding.UTF8.GetBytes("This stays confidential.");

byte[] envelope = HybridEnvelope.Seal(recipient.PublicKey, plaintext);
byte[] recovered = HybridEnvelope.Open(recipient.PrivateKey, envelope);
```

For authenticated confidentiality (the recipient also learns who sent
it), use `SignedHybridEnvelope.Seal`/`Open`.

## 5. Read the samples

The [`samples/`](../samples/README.md) folder has nine focused demos
organized from "round-trip the primitives" up to "full ASP.NET Core
service with zero-downtime key rotation."

## 6. Next

- [SPEC (wire format)](../docs/SPEC.md)
- [Design rationale](../docs/design.md)
- [Threat model](../docs/THREAT-MODEL.md)
- [API reference](api/)
- [Hardening checklist](../HARDENING-CHECKLIST.md) (when you're ready to deploy)
