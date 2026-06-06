# PostQuantum.Hybrid

High-level **hybrid post-quantum cryptography** for .NET. Combines a battle-tested
classical primitive with a NIST-standardized post-quantum algorithm so your
shared secrets and signatures remain secure as long as **either** primitive
holds — defense in depth against both today's attackers and tomorrow's quantum
adversaries.

- **Targets:** .NET 8 and .NET 10
- **Backends:** native `System.Security.Cryptography.MLKem` / `MLDsa` on .NET 10;
  BouncyCastle on .NET 8. Wire-compatible across both.
- **Dependencies:** `BouncyCastle.Cryptography` only.

## Algorithms

| Use case | Default combination | Standards |
|---|---|---|
| Key encapsulation | **X25519 + ML-KEM-768** | RFC 7748 + FIPS 203 |
| Digital signatures | **Ed25519 + ML-DSA-65** | RFC 8032 + FIPS 204 |

## Install

```bash
dotnet add package PostQuantum.Hybrid
```

## Quick start — Hybrid KEM

```csharp
using PostQuantum.Hybrid;

// Recipient: generate a key pair, publish the public key.
using var recipient = HybridKem.GenerateKeyPair();
byte[] publicKeyBytes = recipient.PublicKey.Export();

// Sender: encapsulate against the recipient's public key.
var publicKey = HybridKemPublicKey.Import(publicKeyBytes);
using var encapsulation = HybridKem.Encapsulate(publicKey);

byte[] ciphertext = encapsulation.Ciphertext.ToBytes();   // send to recipient
byte[] sharedSecret = encapsulation.SharedSecret;          // use locally (32 bytes)

// Recipient: decapsulate to recover the same shared secret.
byte[] recoveredSecret = HybridKem.Decapsulate(recipient.PrivateKey, ciphertext);
// recoveredSecret == sharedSecret
```

## Quick start — Hybrid signatures

```csharp
using PostQuantum.Hybrid;

using var signer = HybridSignature.GenerateKeyPair();

byte[] message = "Hello, post-quantum world!"u8.ToArray();
byte[] signature = HybridSignature.Sign(signer.PrivateKey, message);

bool valid = HybridSignature.Verify(signer.PublicKey, message, signature);
```

## Serialization

Every key/ciphertext/signature is a versioned, fixed-size byte blob. Both raw
and PEM encodings are supported.

```csharp
// Raw bytes
byte[] pubBytes = signer.PublicKey.Export();
var pubFromBytes = HybridSignaturePublicKey.Import(pubBytes);

// PEM
string pubPem = signer.PublicKey.ExportPem();
var pubFromPem = HybridSignaturePublicKey.ImportPem(pubPem);
```

| Artifact | Size (bytes) | PEM label |
|---|---|---|
| Hybrid KEM public key | 1217 | `PQH HYBRID KEM PUBLIC KEY` |
| Hybrid KEM private key | 2433 | `PQH HYBRID KEM PRIVATE KEY` |
| Hybrid KEM ciphertext | 1121 | (raw only) |
| Hybrid signature public key | 1985 | `PQH HYBRID SIG PUBLIC KEY` |
| Hybrid signature private key | 4065 | `PQH HYBRID SIG PRIVATE KEY` |
| Hybrid signature | 3374 | (raw only) |
| Shared secret | 32 | (raw only) |

## How it works

### Hybrid KEM combiner

The two component shared secrets are combined with HKDF-SHA256, with both
ciphertexts bound into the `info` parameter so the derived secret depends on
the full transcript:

```
sharedSecret = HKDF-SHA256(
    ikm  = ss_x25519 ‖ ss_mlkem,
    info = "PostQuantum.Hybrid v1 KEM X25519-MLKEM768" ‖ ct_x25519 ‖ ct_mlkem,
    len  = 32 )
```

### Hybrid signature combiner

Both schemes independently sign the message bytes (each does its own internal
hashing). The signatures are concatenated; verification requires **both** to
verify with their respective public keys.

## Security notes

- **Algorithm agility:** The wire format begins with a single-byte algorithm
  identifier so additional combinations can be added without breaking existing
  artifacts.
- **Implicit rejection:** ML-KEM uses FIPS 203's implicit rejection — malformed
  ciphertexts yield pseudorandom secrets rather than throwing. The combined
  hybrid secret will simply differ from the sender's, causing downstream
  decryption to fail authentically.
- **Sensitive material:** `HybridKemPrivateKey`, `HybridSignaturePrivateKey`,
  `HybridKemKeyPair`, `HybridSignatureKeyPair`, and
  `HybridKemEncapsulationResult` all implement `IDisposable` and zero their
  buffers on dispose. Always use `using`.
- **Signature randomization:** ML-DSA signing is randomized by default — two
  signatures over the same data will differ. This is expected.

## Project layout

```
src/PostQuantum.Hybrid/         the library
tests/PostQuantum.Hybrid.Tests/ xUnit tests (run on net8.0 and net10.0)
samples/PostQuantum.Hybrid.Sample/  console demo
```

## License

MIT.
