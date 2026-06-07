# Mutation testing

We use [Stryker.NET](https://stryker-mutator.io/docs/stryker-net/) to
measure the *quality* of the test suite (not just its coverage). A
mutation test changes one byte of source code (a "mutant"), reruns the
tests, and checks whether any test fails. If no test catches the
mutation, the mutant *survived* — meaning that code path is either
untested or tested only superficially.

## Running locally

```bash
dotnet tool install -g dotnet-stryker

# Run against the library
cd src/PostQuantum.Hybrid
dotnet stryker
```

The first run takes 10–30 minutes depending on hardware. Results
appear under `StrykerOutput/<timestamp>/reports/`.

## CI

Mutation testing is not on the per-PR critical path because it's slow.
It runs as a periodic GitHub Action (intended addition, currently
[planned](../docs/ROADMAP.md#lower-priority)). The configuration lives
in [`stryker-config.json`](../stryker-config.json) at the repo root.

## Thresholds

| Score | Status |
|---|---|
| ≥ 85% | high — green |
| 75% – 85% | acceptable |
| 70% – 75% | low — flagged |
| < 70% | break — CI fails |

## Interpreting "survived" mutants

A surviving mutant points to one of three things:

1. **Missing test coverage** — add a test that fails on the mutant.
2. **Equivalent mutant** — the mutation produces semantically identical
   code (rare for crypto). Annotate the source with
   `// stryker disable next-line all : <reason>` if so.
3. **Unreachable code** — delete it.

Cryptographic constant-time invariants are particularly sensitive to
mutations: a test that times out on a mutant is sometimes correct
(timing-sensitive verification) rather than a flaw.
