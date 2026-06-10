# PostQuantum.Hybrid — Specification

This document is the **normative wire-format and algorithm specification** for
PostQuantum.Hybrid v1. It is intended to be sufficient to write a compatible
implementation in another language. The library itself is the reference
implementation.

## Versioning

- **Library version** follows [SemVer](https://semver.org).
- **Wire-format version** is bound to a single-byte **algorithm identifier**
  prefixed to every serialized artifact. Any future change that affects the
  on-the-wire bytes must use a new algorithm identifier so v1 blobs continue
  to parse and verify.

## Algorithm identifiers

| Family | Value | Meaning |
|---|---|---|
| Hybrid KEM | `0x01` | `X25519MlKem768` — X25519 (RFC 7748) + ML-KEM-768 (FIPS 203), HKDF-SHA256 combiner |
| Hybrid KEM | `0x02` | `X25519MlKem768XWing` (**preview**) — same components and byte layout as `0x01`, X-Wing SHA3-256 combiner (see "Combiner") |
| Hybrid signatures | `0x01` | `Ed25519MlDsa65` — Ed25519 (RFC 8032) + ML-DSA-65 (FIPS 204) |

Each family numbers its identifiers independently. The library refuses to
parse blobs whose first byte is not in the supported set.

## Hybrid KEM (`X25519MlKem768`)

### Component sizes

| Quantity | Bytes |
|---|---|
| X25519 public key | 32 |
| X25519 private key (clamped scalar) | 32 |
| X25519 shared secret | 32 |
| ML-KEM-768 encapsulation key | 1184 |
| ML-KEM-768 decapsulation key (FIPS 203 standard encoding) | 2400 |
| ML-KEM-768 ciphertext | 1088 |
| ML-KEM-768 shared secret | 32 |

### Wire formats

All multi-byte integers are little-endian. There are none in v1 — every layout
is a fixed-size concatenation.

```
HybridKemPublicKey   (1217 bytes) := algId(1) || X25519_pub(32)  || MLKEM768_pub(1184)
HybridKemPrivateKey  (2433 bytes) := algId(1) || X25519_priv(32) || MLKEM768_priv(2400)
HybridKemCiphertext  (1121 bytes) := algId(1) || X25519_eph_pub(32) || MLKEM768_ct(1088)
HybridKemSharedSecret(  32 bytes) := raw HKDF output (see "Combiner" below)
```

`X25519_eph_pub` is the **ephemeral** public key the sender generated for this
encapsulation; in DH-KEM terms it is the "ciphertext".

### Encapsulation

```
inputs:  HybridKemPublicKey { X25519_pub, MLKEM768_pub }
outputs: HybridKemCiphertext { X25519_eph_pub, MLKEM768_ct }
         sharedSecret (32 bytes)
```

1. Generate an ephemeral X25519 key pair `(X25519_eph_priv, X25519_eph_pub)`
   using a cryptographically secure RNG.
2. Compute `ss_X = X25519(X25519_eph_priv, X25519_pub)` — 32 bytes.
3. Run `MLKEM768.Encaps(MLKEM768_pub) -> (MLKEM768_ct, ss_M)` — 1088 + 32 bytes.
4. `sharedSecret = Combine(ss_X, ss_M, X25519_eph_pub, MLKEM768_ct)`.
5. Return the assembled `HybridKemCiphertext` and `sharedSecret`.

### Decapsulation

```
inputs:  HybridKemPrivateKey, HybridKemCiphertext
outputs: sharedSecret (32 bytes)
```

1. Compute `ss_X = X25519(X25519_priv, X25519_eph_pub)`.
2. Run `MLKEM768.Decaps(MLKEM768_priv, MLKEM768_ct) -> ss_M`. Per FIPS 203,
   this never throws on a malformed ciphertext; it returns an
   indistinguishable pseudorandom value (implicit rejection).
3. `sharedSecret = Combine(ss_X, ss_M, X25519_eph_pub, MLKEM768_ct)`.
4. Return `sharedSecret`. If the sender's encapsulation was honest and
   intact, this equals the sender's `sharedSecret`; otherwise it diverges
   pseudorandomly and downstream symmetric decryption authentically fails.

### Combiner

```
sharedSecret = HKDF-SHA256(
    ikm  = ss_X || ss_M,
    salt = empty,
    info = label || X25519_eph_pub || MLKEM768_ct,
    L    = 32 )

label = ASCII "PostQuantum.Hybrid v1 KEM X25519-MLKEM768"   (41 bytes)
```

The `info` parameter binds the entire transcript so any tampering with either
ciphertext component yields a different shared secret. This pattern is
analogous to (but distinct from) the X-Wing construction; see
`docs/adr/0003-kem-combiner.md` for rationale.

### Combiner at algorithm-id `0x02` (X-Wing, preview)

Algorithm-id `0x02` uses the same key/ciphertext byte layouts as `0x01`
(classical-first, sizes above) but derives the shared secret with the X-Wing
combiner from draft-connolly-cfrg-xwing-kem:

```
sharedSecret = SHA3-256( label6 || ss_M || ss_X || X25519_eph_pub || X25519_pub )

label6 = 0x5c 0x2e 0x2f 0x2f 0x5e 0x5c   (the 6-byte X-Wing label "\.//^\")
```

`X25519_pub` is the **recipient's** static X25519 public key. Note that
`MLKEM768_ct` is *not* hashed directly — per the X-Wing analysis, `ss_M`
already depends on it (ML-KEM is implicitly-rejecting), while the X25519
transcript must be bound explicitly.

**This is not IETF X-Wing wire interop.** The IETF construction orders
components post-quantum-first and has its own single-blob encodings; `0x02`
applies only the X-Wing *combiner formula* to the v1 byte layout. Strict
IETF X-Wing interop is reserved for a future algorithm-id. See
`docs/adr/0013-xwing-combiner-preview.md`.

## Hybrid signatures (`Ed25519MlDsa65`)

### Component sizes

| Quantity | Bytes |
|---|---|
| Ed25519 public key | 32 |
| Ed25519 private key (seed) | 32 |
| Ed25519 signature | 64 |
| ML-DSA-65 public key | 1952 |
| ML-DSA-65 private key (FIPS 204 standard encoding) | 4032 |
| ML-DSA-65 signature | 3309 |

### Wire formats

```
HybridSignaturePublicKey  (1985 bytes) := algId(1) || Ed25519_pub(32)  || MLDSA65_pub(1952)
HybridSignaturePrivateKey (4065 bytes) := algId(1) || Ed25519_priv(32) || MLDSA65_priv(4032)
HybridSignature           (3374 bytes) := algId(1) || Ed25519_sig(64)  || MLDSA65_sig(3309)
```

### Signing

```
inputs:  HybridSignaturePrivateKey, message
outputs: HybridSignature
```

1. Compute `sig_E = Ed25519.Sign(Ed25519_priv, message)`.
2. Compute `sig_M = MLDSA65.Sign(MLDSA65_priv, message, ctx = empty)`.
   This is "pure" FIPS-204 ML-DSA with an empty context; ML-DSA signing is
   randomized by default, so two signatures over the same message under the
   same key WILL differ.
3. Return `algId || sig_E || sig_M`.

### Verification

```
inputs:  HybridSignaturePublicKey, message, HybridSignature
output:  bool
```

1. If `|signature| != 3374`, return `false`.
2. If `signature[0] != publicKey.algorithmId`, return `false`.
3. Compute `ok_E = Ed25519.Verify(Ed25519_pub, message, sig_E)`.
4. Compute `ok_M = MLDSA65.Verify(MLDSA65_pub, message, sig_M, ctx = empty)`.
5. Return `ok_E AND ok_M`. **Both** must verify.

## PEM encoding

PEM (RFC 7468) is supported with library-specific labels. The body is the
raw byte format above, base64-encoded with 64-character lines.

| Label | Wraps |
|---|---|
| `PQH HYBRID KEM PUBLIC KEY` | `HybridKemPublicKey` |
| `PQH HYBRID KEM PRIVATE KEY` | `HybridKemPrivateKey` |
| `PQH HYBRID SIG PUBLIC KEY` | `HybridSignaturePublicKey` |
| `PQH HYBRID SIG PRIVATE KEY` | `HybridSignaturePrivateKey` |

Ciphertexts and signatures have raw binary forms only; PEM-wrapping them is
not idiomatic.

## Test vectors (informative)

Because all relevant primitives are randomized, test vectors cannot be made
deterministic without exposing internal RNG state. The test suite verifies:

- Sender and receiver agree on the 32-byte shared secret after KEM
  encapsulation/decapsulation.
- Hybrid signatures round-trip via sign/verify.
- Tampering with any byte of any wire artifact causes verification to fail
  (or, for KEM, causes the derived secret to diverge).
- All wire blobs have the exact sizes stated above.

Implementers porting to another language should validate their port by
cross-verifying signatures and KEM transcripts produced by this reference
implementation.
