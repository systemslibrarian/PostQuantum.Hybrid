# PostQuantum.Hybrid — Design

This document explains the **why** behind PostQuantum.Hybrid's design. For the
**what** (precise wire formats), see [SPEC.md](SPEC.md).

## Why hybrid?

Post-quantum primitives are new. ML-KEM and ML-DSA are NIST-standardized
(FIPS 203 / FIPS 204) and built on lattice problems that the cryptographic
community currently believes are hard for both classical and quantum
adversaries — but they have far less battle-testing than X25519 and Ed25519.

A **hybrid construction** combines both worlds so the resulting protocol is
secure as long as *either* component primitive holds:

| Threat scenario | Classical-only (X25519) | PQ-only (ML-KEM) | **Hybrid** |
|---|---|---|---|
| Quantum adversary today | broken | secure | **secure** |
| ML-KEM breaks (cryptanalytic surprise) | secure | broken | **secure** |
| X25519 breaks (unlikely) | broken | secure | **secure** |
| Implementation bug in ML-KEM | possibly safe | broken | **safe** |
| Implementation bug in X25519 | broken | safe | **safe** |

The cost is roughly 2× key size and CPU. For most workloads this is a
forgettable price compared to the asymmetric risk of relying on a single,
relatively new primitive.

## Why these specific algorithms?

### X25519 + ML-KEM-768 (for KEM)

- **X25519** (Curve25519 + DH) — ubiquitous, well-implemented, widely
  audited, fast on every platform .NET supports.
- **ML-KEM-768** (Kyber-768) — NIST Level 3 (~AES-192 equivalent), the
  middle parameter set and the one the IETF picked for TLS 1.3 hybrid
  groups (`X25519MLKEM768`). This makes the construction natural for
  developers transitioning from classical TLS-derived patterns.

### Ed25519 + ML-DSA-65 (for signatures)

- **Ed25519** — the modern default for fast asymmetric signatures, deterministic,
  widely implemented.
- **ML-DSA-65** (Dilithium3) — NIST Level 3, the parameter set NIST themselves
  call out as a sensible general-purpose default.

Both pairs are also the choices the IETF is converging on for hybrid TLS / X.509
certificate composition (see draft-ietf-tls-hybrid-design and Composite Signatures).

## Why ONE combination per family in v1?

Cryptographic agility is valuable; cryptographic *choice* in the public API
is dangerous. v1 exposes exactly one combination per family because:

1. **Almost no one needs a different combination.** ML-KEM-768 is the right
   default for the next decade for nearly every application.
2. **Every additional combination is a new surface to test, document, and
   defend.** Bad combinations (X25519 + ML-KEM-1024, say — mismatched
   security levels) become foot-guns.
3. **Adding combinations later is non-breaking.** The algorithm-id byte in
   the wire format means future combinations can be added without
   invalidating existing keys or ciphertexts.

The `HybridKemAlgorithm` / `HybridSignatureAlgorithm` enums exist explicitly
to enable that future without locking us into a one-size-fits-all API.

## Why the KEM combiner uses HKDF + transcript binding

A naïve hybrid KEM combiner — `KDF(ss_classical || ss_pq)` — is **not
binding**: an attacker who can manipulate ciphertexts can sometimes induce
related-key behavior between sessions.

Binding both ciphertexts into the combiner's `info` parameter ensures that
the derived secret depends on the entire transcript. Any tampering with
either ciphertext component causes the receiver's derived secret to diverge
pseudorandomly from the sender's, and downstream symmetric authenticated
encryption fails to decrypt — which is exactly the failure mode we want.

We use HKDF-SHA256 rather than a bespoke construction (e.g. raw SHA3) for
ecosystem reasons: HKDF is in `System.Security.Cryptography` on every
.NET target, well-understood, and has explicit notions of "salt", "info",
and "expand length" that make the combiner self-documenting.

Related work:
- "X-Wing: General-Purpose Hybrid Post-Quantum KEM" (Barbosa et al., 2024)
  uses a SHA3-based combiner specifically for X25519+ML-KEM-768; the
  authors prove tight IND-CCA security. v1's combiner is in the same
  spirit but uses HKDF-SHA256 for ecosystem availability. A future
  algorithm-id `0x02` could opt into X-Wing precisely.

## Why signatures are not combined by hashing

For hybrid signatures, the two component signatures are produced **over the
same message bytes** and concatenated. Both must verify. There is no
intermediate hash, no domain separator added by us, and no "message
combiner".

This is the simplest construction that is unforgeable when **either**
underlying primitive is unforgeable. Both Ed25519 and ML-DSA do their own
internal hashing, so adding another hash layer would be redundant and would
move the construction out of the well-studied "concatenated signatures"
literature.

Each component signature includes its own algorithm's domain separator
internally, so cross-protocol attacks between Ed25519 and ML-DSA are not
possible.

## Why multi-target net8.0 and net10.0?

- **.NET 8 is LTS** and will be supported through November 2026. A library
  that wants to be "the standard" must work on the most-deployed runtime.
- **.NET 10 brings native ML-KEM and ML-DSA** in
  `System.Security.Cryptography`. Using the native implementation where
  available is strictly better — fewer dependencies, smaller attack
  surface, no second copy of FIPS-validated code.

The wire format is identical across both backends; this was verified by
direct cross-backend interop testing during development (see
`tests/PostQuantum.Hybrid.Tests`).

## Why BouncyCastle for the classical primitives even on .NET 10?

.NET 10 ships ML-KEM and ML-DSA natively but does **not** yet expose
X25519 or Ed25519 as public types. The roadmap suggests both will arrive
in a future .NET release; when they do, PostQuantum.Hybrid will switch to
the native implementations on that target with no public-API change.

## Why explicit `IDisposable` private-key types?

In .NET, the GC has no obligation to zero an unused byte array before
collecting it. Cryptographic key material left lying in unmanaged or
managed memory can be exfiltrated via memory-dump attacks or paging.

`HybridKemPrivateKey`, `HybridSignaturePrivateKey`, `HybridKemKeyPair`,
`HybridSignatureKeyPair`, and `HybridKemEncapsulationResult` all
implement `IDisposable` and call `CryptographicOperations.ZeroMemory` on
their sensitive buffers. The `using` pattern is the intended usage.

## Why an algorithm-id byte at the front of every blob?

A single byte is essentially free, costs no parsing complexity, and is the
difference between "we shipped a wire-format that's stuck forever" and
"we can evolve". The cost-benefit is overwhelmingly in favor of including
it, so we do.

## What's deliberately NOT in v1

- **PKCS#8 / SubjectPublicKeyInfo encoding.** Native .NET's `MLKem.ExportPkcs8PrivateKey`
  uses a single-algorithm SPKI; a hybrid blob has no standard SPKI form yet.
  When IETF PQ-hybrid composite-key OIDs stabilize, we'll add support.
- **Algorithm negotiation.** This is a protocol concern, not a primitives
  concern. The library exposes the algorithm identifier so callers can
  negotiate at their layer.
- **Streaming sign/verify or stream encapsulation.** v1 takes complete
  messages. ML-DSA does not support pre-hashed signing in a generic way
  in .NET 10 yet; once it does, we'll add `SignPreHash` variants.
- **AspNetCore / DI helpers, Roslyn analyzers, dotnet new templates.**
  Planned for follow-up packages: `PostQuantum.Hybrid.AspNetCore`,
  `PostQuantum.Hybrid.Analyzers`, `dotnet new pqhybrid-app`.
- **Hardware acceleration hooks.** Both native .NET and BouncyCastle use
  the best available implementation for the host CPU automatically.
