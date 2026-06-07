# PostQuantum.Hybrid — Benchmarks

[BenchmarkDotNet](https://benchmarkdotnet.org) suite measuring the cost of
the library's core operations on both target frameworks.

## Running

```bash
# All benchmarks, both TFMs
dotnet run --project benchmarks/PostQuantum.Hybrid.Benchmarks --configuration Release

# Single class
dotnet run --project benchmarks/PostQuantum.Hybrid.Benchmarks --configuration Release -- \
    --filter "*HybridKemBenchmarks*"

# Specific runtime
dotnet run --project benchmarks/PostQuantum.Hybrid.Benchmarks --framework net10.0 --configuration Release
dotnet run --project benchmarks/PostQuantum.Hybrid.Benchmarks --framework net8.0  --configuration Release
```

The benchmarks run on whichever TFM you launch with. Compare backends by
running each TFM separately.

## What gets measured

| Benchmark | What it does |
|---|---|
| `HybridKemBenchmarks` | Keygen / Encapsulate / Decapsulate |
| `HybridSignatureBenchmarks` | Sign / Verify at 64 B, 1 KiB, 64 KiB message sizes |
| `HybridSignatureKeyGenBenchmark` | Signature keygen (separated to avoid noise from `[Params]`) |
| `SerializationBenchmarks` | Raw and PEM Export/Import for KEM and signature keys |

Each benchmark runs on both **net8.0** (BouncyCastle backend) and
**net10.0** (native backend), with net8 marked as the baseline. The
ratio column in the BDN output shows how much faster native is.

## Interpretation guidance

- Keygen, sign, verify are dominated by the post-quantum primitive; the
  native net10.0 path is typically several × faster than the BouncyCastle
  path.
- Encap/Decap include both the X25519 agreement (always BC) and the
  ML-KEM operation (native on net10, BC on net8). The X25519 portion is
  ~constant across TFMs.
- Serialization is a memory-bound `Buffer.MemoryCopy` plus a base64 round
  for PEM. No backend variation expected.

## Future work

A perf-regression gate in CI is on the [KNOWN-GAPS](../../KNOWN-GAPS.md)
list. The intended flow is: store a `baseline.json` per platform, fail
a PR if any benchmark regresses more than N%.
