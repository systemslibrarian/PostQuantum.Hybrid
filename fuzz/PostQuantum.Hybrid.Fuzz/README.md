# PostQuantum.Hybrid — Fuzz tests

Property-style fuzz tests that drive thousands of random and mutated
inputs through the library's parsers and asserts the only failure modes
are clean exceptions (`CryptographicException`, `FormatException`,
`ArgumentNullException`). Anything else is a bug.

## Running

```bash
dotnet test fuzz/PostQuantum.Hybrid.Fuzz --configuration Release
```

The seeds are deterministic, so a failure is reproducible without
recording the offending input.

## What this is NOT

This project is **not** AFL/libFuzzer-style coverage-guided fuzzing. It
is *property-based* fuzz testing — fixed-iteration loops with seeded
PRNG inputs. Coverage-guided fuzzing via SharpFuzz / AFL.NET is on the
[KNOWN-GAPS](../../KNOWN-GAPS.md) list and would live in a separate
harness.

## Adding a new fuzz test

When you add a new parser or import method to the public API, add a
`Fuzz*` test here. The body should:

1. Generate `Iterations` (1000 by default) random inputs.
2. Call the parser inside `AssertOnlyExpectedExceptions(...)`.
3. Use a hex-recognizable seed (`0xC0FFEE`, `0xBEEF`, etc.) so a failing
   seed prints as a readable hex constant.
