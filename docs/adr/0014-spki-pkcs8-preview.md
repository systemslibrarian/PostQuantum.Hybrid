# ADR 0014: SubjectPublicKeyInfo / PKCS#8 encoding with placeholder OIDs (preview)

**Status:** Accepted (preview)

## Context

The v1 library serializes hybrid keys as a versioned, fixed-size byte
blob with an algorithm-id byte (see [SPEC](../SPEC.md) and
[ADR 0007](0007-versioned-wire-format.md)). That format is simple and
self-describing for callers that stay inside the PostQuantum.Hybrid
ecosystem.

But many downstream stores expect ASN.1-framed material:

- Embedding a public key inside an X.509 certificate template needs a
  `SubjectPublicKeyInfo`.
- Persisting a private key in a PKCS#8-aware key store needs a
  `PrivateKeyInfo`.
- Some KMS / HSM APIs round-trip via PKCS#8 only.

The IETF LAMPS WG has drafts (`draft-ietf-lamps-pq-composite-kem` and
`draft-ietf-lamps-pq-composite-sig`) that will eventually assign
official OIDs for hybrid composite constructions. Those OIDs are not
yet final; both drafts are still being revised.

## Decision

Ship the **framing now, OIDs as preview placeholders**:

- `HybridKemPublicKey.ExportSubjectPublicKeyInfo()` and
  `ImportSubjectPublicKeyInfo(ReadOnlySpan<byte>)` round-trip the v1
  wire blob inside a valid X.509 `SubjectPublicKeyInfo` envelope.
- `HybridKemPrivateKey.ExportPkcs8PrivateKey()` and
  `ImportPkcs8PrivateKey(ReadOnlySpan<byte>)` round-trip the v1 wire
  blob inside a valid PKCS#8 `PrivateKeyInfo` envelope.
- Same four methods on `HybridSignaturePublicKey` /
  `HybridSignaturePrivateKey`.

The algorithm OIDs live under the IANA Example PEN
`1.3.6.1.4.1.32473` (RFC 5612). Specifically:

| Construction | OID |
|---|---|
| Hybrid KEM X25519+ML-KEM-768, HKDF-SHA256 combiner | `1.3.6.1.4.1.32473.1.1.1` |
| Hybrid KEM X25519+ML-KEM-768, X-Wing combiner | `1.3.6.1.4.1.32473.1.1.2` |
| Hybrid signature Ed25519+ML-DSA-65 | `1.3.6.1.4.1.32473.1.2.1` |

The inner key material inside the BIT STRING (SPKI) or OCTET STRING
(PKCS#8) is the existing PostQuantum.Hybrid wire format, byte-for-byte.
Decoding therefore reduces to "read the inner bytes, hand them to the
existing `Import` path."

## Rationale

- **Structurally valid framing matters.** A consumer that just needs
  to *embed* a hybrid public key inside an X.509 extension or an
  encrypted PKCS#8 store does not need IETF-allocated OIDs to do so —
  any registered OID works. RFC 5612 explicitly carved out
  `1.3.6.1.4.1.32473` for exactly this purpose.
- **The encoder is `System.Formats.Asn1`-based.** No new dependency,
  no hand-written ASN.1 parser, and the output passes through
  third-party DER decoders (the test suite confirms this against
  `AsnReader` directly).
- **Replacement is a non-issue when LAMPS finalizes.** The OID
  constants live in `Internal.Pkcs8SpkiCodec`; flipping them and
  bumping the algorithm-id list is a single-file change. The wire
  shape of the inner bytes does not change.

## Consequences

- New public surface on each of the four key types:
  `ExportSubjectPublicKeyInfo()` / `ImportSubjectPublicKeyInfo()` on
  public-key types; `ExportPkcs8PrivateKey()` /
  `ImportPkcs8PrivateKey()` on private-key types.
- XML docs explicitly call out the preview status and the
  placeholder OID story.
- When LAMPS finalizes, the OIDs change and existing blobs at the
  preview OIDs continue to decode (the codec accepts the placeholder
  OIDs unconditionally; the IETF-final OIDs will be added as
  additional accepted values to preserve backward compatibility for
  early adopters).
- The inner bytes are deliberately the existing wire format including
  the algorithm-id byte. That keeps `Import(rawBytes)` and
  `Import...Info(envelope)` semantically identical once the envelope
  is unwrapped.
- Tests cover: KEM v1 + X-Wing SPKI round-trips, KEM PKCS#8 round-trip
  with semantic encap/decap, signature SPKI + PKCS#8 round-trips,
  rejection of a wrong-OID SPKI (we use RSA's OID as a non-match
  fixture), and direct `AsnReader` parse to confirm the emitted bytes
  are DER-valid.
