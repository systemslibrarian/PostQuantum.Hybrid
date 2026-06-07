# ADR 0009: PostQuantum.Hybrid.Envelopes as a separate package

**Status:** Accepted

## Context

The primitives in `PostQuantum.Hybrid` produce a 32-byte KEM shared
secret. Application code that just wants "encrypt this message for that
recipient" has to compose four things on top:

1. KEM encapsulation against the recipient's public key.
2. HKDF-Expand from the 32-byte shared secret to a 32-byte AES key,
   with a purpose-specific `info` and the KEM ciphertext bound in.
3. AES-256-GCM encryption with a fresh nonce and the KEM ciphertext
   bound in as `associatedData`.
4. Wire framing so the recipient can find the KEM ciphertext, nonce,
   tag, and AES ciphertext in the right order.

Most callers will get one of those steps wrong if asked to do it
themselves. Three of our analyzer rules (PQH002 SharedSecret-without-HKDF,
PQH003 Decapsulate-before-Verify, PQH005 AEAD-without-KEM-binding)
exist specifically to catch the most common mistakes.

## Options considered

### A. Document the pattern in `SECURE-USAGE.md` and ship samples

What we did at v1.0 for the first preview. The pattern is correct and
easy to follow, but it's eight lines of cryptography that someone has
to write correctly. The samples are reference code; they get
copy-pasted into production with subtle mutations.

### B. Add `HybridEnvelope.Seal/Open` to the core `PostQuantum.Hybrid`
package

Simpler dependency graph but couples the primitives library to AES-GCM
and HKDF choices. The core library would also have to grow a Sign+Encrypt
("signed envelope") variant.

### C. Ship a separate `PostQuantum.Hybrid.Envelopes` package (our
choice)

Keeps `PostQuantum.Hybrid` minimal and primitive-shaped. Envelopes is
its own package that depends on the primitives package and provides:

- `HybridEnvelope.Seal(pub, plaintext)` / `Open(priv, envelope)` — the
  anonymous (encrypted-only) variant.
- `SignedHybridEnvelope.Seal(senderSigPriv, recipientKemPub, plaintext)`
  / `Open(senderSigPub, recipientKemPriv, envelope)` — the
  authenticated variant. Verifies sender signature BEFORE decapsulating.

## Decision

Ship `PostQuantum.Hybrid.Envelopes` as a separate package. Default
HKDF/AES-GCM choices are baked in; if a caller wants different choices
they should reach for the primitives directly. The wire format begins
with a 1-byte version (currently `0x01`) so future variants can be
added.

## Consequences

- The 80%-90% case for hybrid PQ encryption is now one call to seal +
  one call to open. The misuse opportunities from analyzer rules
  PQH002/PQH003/PQH005 disappear for callers using Envelopes.
- The `EnvelopeFormat` internal in
  `PostQuantum.Hybrid.AspNetCore`'s `IDataProtector` adapter mirrors
  the wire format so an AspNetCore-protected blob is interoperable
  with a CLI tool using Envelopes (when the purpose chain is empty).
- New Envelopes variants would each get a new version byte. The package
  is small and stable; we don't expect frequent additions.
