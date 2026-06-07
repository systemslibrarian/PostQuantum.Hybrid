# ADR 0007: Versioned wire format with algorithm-id byte

**Status:** Accepted

## Context

Cryptographic libraries that ship "v1" without a versioned wire format
discover, three years later, that their on-the-wire blobs are stuck forever.
Adding a second algorithm requires either a flag day, a new package, or
heuristic detection — all bad.

We want PostQuantum.Hybrid to be able to add `X25519MlKem1024`,
`Ed448MlDsa87`, X-Wing, SLH-DSA, or whatever else the next decade
standardizes without breaking any deployed v1 deployment.

## Decision

Every serialized artifact begins with a **single algorithm-identifier
byte**. The byte's value selects which combination is used:

| Family | Byte | Combination |
|---|---|---|
| Hybrid KEM | `0x01` | X25519 + ML-KEM-768 |
| Hybrid signatures | `0x01` | Ed25519 + ML-DSA-65 |

Each family numbers its own identifier space. `0x00` is reserved (never
emitted; used as a parse error sentinel if a blob is zero-padded). Values
`0x80`–`0xFF` are reserved for future extension.

## Rationale

- **One byte costs nothing.** ~0.08% overhead on the smallest blob (a
  hybrid sig public key).
- **Parseability over time is the highest-value property** of a wire
  format. Lose that and the library's ecosystem fragments.
- **No need for length prefixes.** Within a given algorithm identifier,
  every component is fixed-size (32, 1184, 2400, etc.). The total length
  is implied by the identifier.
- **No need for ASN.1 / TLV.** We are not negotiating across heterogeneous
  parser stacks; we are exchanging artifacts inside a controlled .NET
  ecosystem. A 1-byte version tag plus fixed-size concatenation is the
  simplest thing that could possibly work.

## Consequences

- On deserialization, the library reads byte 0, dispatches on it, and
  parses the rest with the known component sizes for that combination.
  Any unknown identifier → `CryptographicException`.
- On serialization, the library writes byte 0 from the typed
  `HybridKemAlgorithm` / `HybridSignatureAlgorithm` enum value.
- Future additions: pick a new byte, add the enum value, add a new
  branch in the dispatch. v1 blobs continue to parse unchanged.
- PEM labels (`PQH HYBRID KEM PUBLIC KEY`, etc.) are deliberately
  algorithm-*family*-scoped, not algorithm-*combination*-scoped, so a
  future combination uses the same label. The blob inside identifies
  the specific combination via its first byte.
