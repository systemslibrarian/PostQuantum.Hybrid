# ADR 0003: HKDF-SHA256 KEM combiner with transcript binding

**Status:** Accepted

## Context

A hybrid KEM produces two component shared secrets, `ss_classical` and
`ss_pq`. We need a deterministic, secure way to combine them into a single
32-byte hybrid shared secret that:

1. Is IND-CCA secure if **either** component KEM is IND-CCA secure.
2. Binds the full transcript so swapping either ciphertext changes the
   derived secret.
3. Uses primitives that are universally available across our target
   frameworks without extra dependencies.

## Options considered

### A. Naïve concatenation: `KDF(ss_classical || ss_pq)`

Simple but **not transcript-binding**. An adversary who can substitute
ciphertexts can sometimes create cross-session attacks. Insufficient.

### B. X-Wing (Barbosa et al., 2024)

```
SS = SHA3-256(label || ss_M || X25519(eph_priv, recipient_pub) || eph_pub || recipient_pub)
```

*(Note, 2026-06-10: the formula above reflects the early draft; the current
IETF draft hashes the label **last**. See the amendment in ADR 0013.)*

A published, peer-reviewed construction with a tight IND-CCA proof. It is
*specifically* designed for X25519 + ML-KEM-768. The drawback for us:
SHA3-256 is not in the BCL on every TFM, requiring BouncyCastle or
`Org.BouncyCastle.Crypto.Digests.Sha3Digest`.

### C. HKDF-SHA256 with transcript binding (our choice)

```
SS = HKDF-SHA256(
    ikm  = ss_classical || ss_pq,
    info = LABEL || ct_classical || ct_pq,
    L    = 32 )
```

HKDF-SHA256 is in `System.Security.Cryptography.HKDF` from .NET 6+; it's
universally available on every TFM we target and on every PQ-capable .NET
TFM going forward. Binding both ciphertexts into `info` provides the
transcript binding we need.

## Decision

We use option **C: HKDF-SHA256 with transcript binding**.

```
sharedSecret = HKDF-SHA256(
    ikm  = ss_X || ss_M,
    salt = empty,
    info = "PostQuantum.Hybrid v1 KEM X25519-MLKEM768" || ct_X || ct_M,
    L    = 32 )
```

## Rationale

- **Zero new dependencies.** HKDF is in the BCL; we don't add SHA3.
- **Ecosystem familiarity.** Developers can read this combiner without
  needing to study X-Wing's specific construction.
- **Transcript-binding is preserved.** Both ciphertexts feed into HKDF's
  `info`, so any tampering changes the derived secret. This is the same
  binding property X-Wing achieves with its `recipient_pub` and `eph_pub`
  fields, just expressed differently.
- **Forward compatibility.** A future algorithm-id `0x02` can opt into
  X-Wing precisely if the ecosystem standardizes there.

## Consequences

- We are **not bit-compatible with X-Wing**. A blob produced by
  PostQuantum.Hybrid `0x01` cannot be decrypted by an X-Wing implementation
  and vice versa. This is by design — we own the algorithm-id namespace.
- The combiner's security is the security of HKDF as a KDF (which is
  proven secure when SHA-256 behaves as a PRF), composed with the security
  of each component KEM. Standard hybrid-KEM proof techniques apply.

## References

- [RFC 5869: HKDF](https://datatracker.ietf.org/doc/html/rfc5869)
- [FIPS 203: ML-KEM](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
- [X-Wing: General-Purpose Hybrid Post-Quantum KEM (Barbosa et al., 2024)](https://eprint.iacr.org/2024/039)
- [Bindel et al.: "Hybrid Key Encapsulation Mechanisms and Authenticated Key Exchange" (2019)](https://eprint.iacr.org/2018/903)
