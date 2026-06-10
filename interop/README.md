# Cross-implementation interop checks

Validates that the ML-KEM-768 and ML-DSA-65 primitives this library
wraps agree with **independent implementations** — Go's standard
library `crypto/mlkem` (FIPS 203) for the KEM, and `cloudflare/circl`'s
`sign/mldsa/mldsa65` (FIPS 204) for the signature scheme. The in-repo
KAT suites prove each backend matches NIST's published vectors; this
suite additionally catches the "both of our backends share the same
bug" failure class on live, randomly generated keys, in both directions.

| Piece | What it is |
|---|---|
| `go/` | Go CLI: `mlkem-{pubkey,encap,decap}` via stdlib `crypto/mlkem`, `mldsa-{pubkey,sign,verify}` via `cloudflare/circl` |
| `dotnet/` | .NET CLI over the same primitive calls the library's backends make (BouncyCastle on net8.0/net10.0, `--backend=native` for `System.Security.Cryptography.{MLKem,MLDsa}` on .NET 10) |
| `.github/workflows/interop.yml` | Two weekly jobs (`mlkem`, `mldsa`): same seed → identical encapsulation/verification keys; Go produces → .NET consumes; .NET produces → Go consumes |

All values cross the process boundary as lowercase hex, one per line.
Seed sizes: ML-KEM uses the 64-byte FIPS 203 `d || z` form; ML-DSA uses
the 32-byte FIPS 204 ξ seed. ML-DSA signing uses empty context on both
sides (BC `deterministic: true`, native `context: default`, Go
`SignTo(..., randomized=false, ...)`).

These projects are deliberately **not** part of `PostQuantum.Hybrid.slnx`
— they are CI tooling, not shippable surface, and the Go toolchain is not
a build prerequisite for the library.

The classical primitives (X25519, Ed25519) are still checked only against
their Wycheproof vector suites in the main test project — Go's stdlib
exposes these but they're already well-covered. See `KNOWN-GAPS.md`.
