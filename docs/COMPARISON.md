# When to use PostQuantum.Hybrid (and when not)

A frank comparison against the alternatives. This is what someone
evaluating the library should read **before** the API docs.

## Use PostQuantum.Hybrid when…

- You want **hybrid post-quantum cryptography in .NET** with as little
  rope as possible to hang yourself with.
- You need to deploy on **.NET 8 LTS** today and want a smooth upgrade
  path to .NET 10 native cryptography without changing your code or
  your wire format.
- You want a **single small dependency** (BouncyCastle) rather than
  wiring a half-dozen primitives together yourself.
- You care that the **wire format is versioned** so today's blobs
  remain parseable forever.
- You want **build-time misuse detection** via Roslyn analyzers
  (PQH001 today; more rules coming).
- You want **honest, reviewer-friendly documentation** — spec, threat
  model, ADRs, hardening checklist, known-gaps — that you don't have
  to reverse-engineer from source.

## Use something else when…

- You need **TLS 1.3 hybrid key exchange.** Use `SslStream` /
  `HttpClient` on .NET 10, which now supports the
  `X25519MLKEM768` group natively at the transport layer.
- You need to **interop with another language/runtime via a
  standardized hybrid container** (e.g. X.509 with composite-PQ OIDs).
  Wait for IETF LAMPS WG to finish, or use the .NET BCL's lower-level
  `MLKem`/`MLDsa` types directly to build your own composite blob.
- You need **only the post-quantum half** (no classical fallback) on
  .NET 10. Use `System.Security.Cryptography.MLKem` / `MLDsa` directly.
- You need **stateless hash-based signatures (SLH-DSA / SPHINCS+)**.
  PostQuantum.Hybrid doesn't ship them yet; use the BCL or BouncyCastle
  directly.
- You need a **JWT signing/validation pipeline.** Use
  [`PostQuantum.Jwt`](https://github.com/systemslibrarian/postquantum-jwt)
  — a sibling project specifically for hybrid JWTs.

## Comparison table

|                         | PostQuantum.Hybrid | Raw BCL (.NET 10) + hand-rolled X25519/Ed25519 | Raw BouncyCastle | Classical-only (libsodium, etc.) |
|---|---|---|---|---|
| **Hybrid KEM in one call** | ✅ | ❌ (you write the combiner) | ❌ (you write the combiner) | ❌ (no PQ) |
| **Hybrid signatures in one call** | ✅ | ❌ (you write the wrapper) | ❌ (you write the wrapper) | ❌ (no PQ) |
| **Versioned wire format** | ✅ | ❌ (your problem) | ❌ (your problem) | n/a |
| **PEM serialization** | ✅ | ❌ | ✅ (component-by-component) | ✅ |
| **`net8.0` support** | ✅ | ❌ (no PQ in BCL) | ✅ | ✅ |
| **`net10.0` support** | ✅ native PQ | ✅ | ✅ but slower | ✅ |
| **Cross-backend wire-compatible** | ✅ same blob on both TFMs | n/a | n/a | n/a |
| **Build-time misuse analyzer** | ✅ (PQH001 today) | ❌ | ❌ | ❌ |
| **Disposable secret types** | ✅ all | ✅ for some | ✅ for some | ✅ |
| **HKDF + transcript-bound combiner** | ✅ built in | ❌ (your problem) | ❌ (your problem) | n/a |
| **Documented threat model** | ✅ | ❌ | partial | partial |
| **Production samples** | ✅ 6 demos | ❌ | ❌ | ❌ |
| **Dependency count** | 1 | 0 | 1 | 1 |

## "Should I use PostQuantum.Hybrid or PostQuantum.Jwt?"

They solve different problems and you can use both.

- **`PostQuantum.Jwt`** signs and validates JWTs (RFC 7519 token format)
  with hybrid PQ algorithms. Use it if your app's authentication flow
  is "send a token, validate the token".
- **`PostQuantum.Hybrid`** is the underlying primitives — hybrid KEM
  and hybrid signatures — without the JWT envelope. Use it if you're
  building anything *other* than JWT-shaped auth flows: file encryption,
  custom protocols, KEM-based key wrapping, signed releases, etc.

## "Is this the right level of abstraction for me?"

PostQuantum.Hybrid sits **one layer above** raw `MLKem` / `MLDsa`. If
you have an application that needs to:

- exchange short messages between two parties
- sign artifacts and let many parties verify
- derive an AEAD key from a fresh KEM exchange

…PostQuantum.Hybrid is the right level.

If you have an application that needs to:

- run a multi-message session protocol with key rotation, replay
  protection, and forward secrecy at the protocol layer
- negotiate algorithms across heterogeneous clients
- interop at the X.509 / PKIX layer with external infrastructure

…you should build a protocol layer on top of PostQuantum.Hybrid (or
use a higher-level library that does this for you).

## "Is the cryptography here mainstream enough to trust?"

The primitives are NIST-standardized (FIPS 203, FIPS 204) and IETF
non-controversial (X25519, Ed25519). The **construction** is
straightforward: the KEM combiner is a transcript-binding HKDF (see
[ADR 0003](adr/0003-kem-combiner.md) for the comparison with X-Wing,
which is a peer-reviewed alternative for the same algorithm
combination); the signature combiner is the textbook concatenated
both-must-verify form (see [ADR 0004](adr/0004-signature-concat.md)).

The library has not been externally audited as of v1.0. We are explicit
about that in [KNOWN-GAPS.md](../KNOWN-GAPS.md) and in the
[ROADMAP-TO-1.0.md](ROADMAP-TO-1.0.md).
