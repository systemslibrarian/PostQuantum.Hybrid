# Cross-implementation interop checks

Validates that the ML-KEM-768 primitives this library wraps agree with an
**independent implementation** — Go's standard library `crypto/mlkem`
(FIPS 203). The in-repo KAT suites prove each backend matches NIST's
published vectors; this suite additionally catches the "both of our
backends share the same bug" failure class on live, randomly generated
keys, in both directions.

| Piece | What it is |
|---|---|
| `go/` | Go CLI over `crypto/mlkem` (stdlib only): `mlkem-pubkey`, `mlkem-encap`, `mlkem-decap` |
| `dotnet/` | .NET CLI over the same primitive calls the library's `MlKemBackend` makes (BouncyCastle on net8.0/net10.0, `--backend=native` for `System.Security.Cryptography.MLKem` on .NET 10) |
| `.github/workflows/interop.yml` | Weekly driver: same seed → identical encapsulation keys; Go encapsulates → .NET decapsulates; .NET encapsulates → Go decapsulates |

All values cross the process boundary as lowercase hex, one per line.
The ML-KEM private seed is the 64-byte FIPS 203 `d || z` form.

These projects are deliberately **not** part of `PostQuantum.Hybrid.slnx`
— they are CI tooling, not shippable surface, and the Go toolchain is not
a build prerequisite for the library.

ML-DSA-65 cross-implementation checks are planned (Go's stdlib does not
ship ML-DSA; candidate: `cloudflare/circl`). See `KNOWN-GAPS.md`.
