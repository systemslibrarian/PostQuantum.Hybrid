# Testing

What this project's test suite *proves*, where each suite lives, and how
to run it. Written for reviewers who want to know whether they can trust
the green checkmark.

## The pyramid

```
              ┌────────────────────────────────────────┐
              │  Mutation testing (Stryker, periodic) │  ← test quality
              ├────────────────────────────────────────┤
              │  Coverage-guided fuzzing (planned)    │
              ├────────────────────────────────────────┤
              │  Property-style fuzz tests             │  ← parser robustness
              │  fuzz/PostQuantum.Hybrid.Fuzz          │
              ├────────────────────────────────────────┤
              │  Integration tests                     │
              │  EndToEndScenarioTests +               │  ← real workflows
              │  PostQuantum.Hybrid.AspNetCore.Tests   │
              ├────────────────────────────────────────┤
              │  Unit tests                            │  ← contract behavior
              │  tests/PostQuantum.Hybrid.Tests        │
              │  tests/PostQuantum.Hybrid.Analyzers.   │
              │    Tests                               │
              └────────────────────────────────────────┘
```

## What each suite proves

### `tests/PostQuantum.Hybrid.Tests` — 85 tests, runs on both TFMs

| File | What it proves |
|---|---|
| `HybridKemTests` | KEM round-trip, tamper detection on either half, wrong-key behavior, malformed-input rejection, dispose semantics. |
| `HybridSignatureTests` | Signature round-trip, tamper detection on either half, wrong-key/wrong-message behavior, ML-DSA randomization. |
| `WireFormatTests` | Algorithm-id byte is correct and dispatch works. |
| `AlgorithmSizesTests` | Pins the byte counts that `docs/SPEC.md` advertises as the public contract. |
| `PemRobustnessTests` | PEM parser accepts CRLF, leading/trailing whitespace, rejects missing markers / wrong labels / invalid base64 / valid-but-wrong-length. |
| `KemEdgeCaseTests` | Span/typed overload equivalence, 25-iteration repeated round trip, deterministic implicit-rejection behavior. |
| `SignatureEdgeCaseTests` | Empty message; 1 B, 16 B, 1 KiB, 64 KiB, 1 MiB message sizes; Unicode; tampered-classical-only / tampered-pq-only verify. |
| `ConcurrencyTests` | 50-way parallel keygen/sign/verify/encap on shared public keys. |
| `EndToEndScenarioTests` | Full sign-then-encrypt round-trip mirroring `samples/SecureMessenger`, with tamper-rejection assertions. |

**Both TFMs must pass.** A test is not "green" until it passes on
`net8.0` (BouncyCastle backend) AND `net10.0` (native backend). This
gives implicit cross-backend validation of the wire formats.

### `fuzz/PostQuantum.Hybrid.Fuzz` — 9 fuzz tests, ~7,200 inputs per run, both TFMs

Property-style fuzzing with deterministic seeds. Each test drives N
random/mutated inputs through a parser and asserts the *only* failure
modes are clean exceptions (`CryptographicException`, `FormatException`,
`ArgumentNullException`, `ArgumentOutOfRangeException`). Any other
exception is a parser bug.

Covers: `HybridKemPublicKey.Import`, `HybridKemPrivateKey.Import`,
`HybridKemCiphertext.FromBytes`, `HybridSignaturePublicKey.Import`,
`HybridSignaturePrivateKey.Import`, `HybridSignature.Verify`,
`HybridKemPublicKey.ImportPem`, plus bit-flip mutations of valid
artifacts.

### `tests/PostQuantum.Hybrid.Analyzers.Tests` — 8 tests

A hand-rolled in-memory test harness (avoids the legacy framework
dependencies that the official `Microsoft.CodeAnalysis.Testing` packages
pull in). Proves PQH001 fires on `var pair = HybridKem.GenerateKeyPair()`
and does NOT fire on `using var pair = ...`, `using (var pair = ...) {}`,
or unrelated types.

### `tests/PostQuantum.Hybrid.AspNetCore.Tests` — 6 tests, both TFMs

DI smoke tests: registration from inline PEM, from file path, from
`IConfiguration`, error cases (missing config, missing key file),
singleton lifetime.

## What's NOT in the test suite

- **NIST KAT vectors.** See [KNOWN-GAPS.md](../KNOWN-GAPS.md#no-nist-kat-known-answer-test-vectors).
- **Coverage-guided fuzzing.** Property-style fuzzing only. See
  [KNOWN-GAPS.md](../KNOWN-GAPS.md#property-style-fuzz-tests-but-no-coverage-guided-fuzzing).
- **Side-channel testing.** Not in scope.
- **External-library interop tests.** No test exchanges bytes with
  OpenSSL or another non-.NET library — there is no standardized
  hybrid-blob format to exchange.

## Running

```bash
# Full test pyramid except mutation testing
dotnet test PostQuantum.Hybrid.slnx --configuration Release

# Just the library tests, single TFM
dotnet test tests/PostQuantum.Hybrid.Tests --framework net10.0

# Just the fuzz tests
dotnet test fuzz/PostQuantum.Hybrid.Fuzz

# Mutation testing (slow: 10–30 min)
dotnet stryker
```

## Test counts (v1.0)

| Suite | Tests | TFMs | Total runs |
|---|---:|---:|---:|
| `PostQuantum.Hybrid.Tests` | 85 | 2 | 170 |
| `PostQuantum.Hybrid.Fuzz` | 9 | 2 | 18 |
| `PostQuantum.Hybrid.Analyzers.Tests` | 8 | 1 | 8 |
| `PostQuantum.Hybrid.AspNetCore.Tests` | 6 | 2 | 12 |
| **Total** | **108** | — | **208** |

## CI

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs the full
test suite on `ubuntu-latest`, `windows-latest`, and `macos-latest`.
A change is "green" only when all three matrix cells pass.

[`.github/workflows/codeql.yml`](../.github/workflows/codeql.yml) runs
CodeQL static analysis weekly and on every PR to `main`.

[`.github/workflows/scorecard.yml`](../.github/workflows/scorecard.yml)
runs the OpenSSF Scorecard weekly and uploads SARIF results.

## Reading test failures

- **A single-TFM failure** (e.g. green on net10.0, red on net8.0)
  usually means a behavioral drift between the BouncyCastle and native
  backends. Investigate the relevant `MlKemBackend` /
  `MlDsaBackend` path; do not "fix" by special-casing the test.
- **A fuzz test failure** means a parser threw an unexpected exception
  type. Treat as a release blocker. Add the failing seed to the
  regression tests inline before fixing.
- **A PQH001 false positive** in user code is a real bug — please file
  it. The analyzer is conservative by design.
