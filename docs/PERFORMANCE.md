# Performance

Measured numbers, not vibes. Run `dotnet run --project benchmarks/PostQuantum.Hybrid.Benchmarks --framework net10.0 --configuration Release` to reproduce.

## Test hardware (reference baseline)

```
BenchmarkDotNet v0.15.8
Windows 11 26200.8457 (25H2)
Intel Core Ultra 7 256V @ 2.20 GHz, 8 logical / 8 physical cores
GC: Concurrent Server
```

Numbers will scale with your hardware; cross-machine comparisons should
use the *ratios*, not the absolute milliseconds.

## Hybrid KEM (X25519 + ML-KEM-768)

| Operation | net10.0 native | net8.0 BouncyCastle | Native speedup | Native allocation reduction |
|---|---:|---:|---:|---:|
| `HybridKem.GenerateKeyPair()` | 277 µs / 6.3 KB | 591 µs / 29.2 KB | **2.1×** | **4.6×** less |
| `HybridKem.Encapsulate(pub)` | 503 µs / 6.2 KB | 978 µs / 35.7 KB | **1.9×** | **5.8×** less |
| `HybridKem.Decapsulate(priv, ct)` | 322 µs / 3.1 KB | 861 µs / 39.9 KB | **2.7×** | **12.9×** less |

## Hybrid signatures (Ed25519 + ML-DSA-65)

| Operation | net10.0 native | net8.0 BouncyCastle | Native speedup | Native allocation reduction |
|---|---:|---:|---:|---:|
| `HybridSignature.GenerateKeyPair()` | 1.80 ms / 9.5 KB | (not measured separately) | n/a | n/a |
| `HybridSignature.Sign(priv, 64 B)` | 1.63 ms / 11.4 KB | 4.17 ms / 640.3 KB | **2.6×** | **56×** less |
| `HybridSignature.Sign(priv, 1 KiB)` | 1.70 ms / 13.1 KB | 5.03 ms / 587.1 KB | **3.0×** | **45×** less |
| `HybridSignature.Sign(priv, 64 KiB)` | 3.23 ms / 139.1 KB | 5.11 ms / 775.8 KB | **1.6×** | **5.6×** less |
| `HybridSignature.Verify(pub, 64 B)` | 583 µs / 7.1 KB | 1.14 ms / 189.1 KB | **2.0×** | **26.5×** less |
| `HybridSignature.Verify(pub, 1 KiB)` | 582 µs / 8.8 KB | 1.23 ms / 190.8 KB | **2.1×** | **21.7×** less |
| `HybridSignature.Verify(pub, 64 KiB)` | 1.56 ms / 134.8 KB | 2.73 ms / 316.8 KB | **1.7×** | **2.3×** less |

## Headline takeaways

- **The native .NET 10 PQ implementations are 2–3× faster** than the
  BouncyCastle backend, and dramatically more memory-efficient (up to
  56× fewer allocations on signing). Upgrade to .NET 10 when you can.
- **Hybrid is not a meaningful tax over the post-quantum half alone.**
  The classical X25519 / Ed25519 components add tens of microseconds,
  not milliseconds. The cost you pay for going hybrid is dominated by
  ML-KEM / ML-DSA itself, not by combining.
- **Signing is the most expensive operation** at ~1.6–3.2 ms native /
  ~4–5 ms BC depending on message size. ML-DSA's rejection sampling is
  the bottleneck; nothing the library does meaningfully changes this.
- **Verify is faster than sign**, ~0.6–1.6 ms native. Most asymmetric
  applications care more about verify throughput than sign throughput
  (one signer, many verifiers); the relevant axis is fast here.

## What "fast enough" looks like in production

| Workload | Verdict |
|---|---|
| Web request signed on hot path | ✅ 1.6–3 ms sign is acceptable on a request-response API where the request already does at least a database round-trip. |
| High-throughput message signing (>1k/s per core) | ⚠️ ML-DSA sign at ~3 ms/op is ~330 ops/s per core. For higher throughput, batch the signing offline or shard signers. |
| Verify-heavy workload (CDN, edge auth) | ✅ 0.6 ms verify = ~1700 ops/s per core on the test box. Edge nodes scale by parallelism easily. |
| KEM-derived session keys (e.g. one per HTTP connection) | ✅ ~1 ms total to establish (encap + AES-GCM setup) is far below network RTT. |

## Reproducing locally

```bash
# All benchmarks, current TFM
dotnet run --project benchmarks/PostQuantum.Hybrid.Benchmarks --framework net10.0 --configuration Release

# Single class
dotnet run --project benchmarks/PostQuantum.Hybrid.Benchmarks --framework net10.0 --configuration Release -- --filter "*HybridKemBenchmarks*"

# Compare backends — run twice
dotnet run --project benchmarks/PostQuantum.Hybrid.Benchmarks --framework net8.0  --configuration Release
dotnet run --project benchmarks/PostQuantum.Hybrid.Benchmarks --framework net10.0 --configuration Release
```

Numbers in this document were captured with
`--warmupCount 2 --iterationCount 3 --invocationCount 16`. BenchmarkDotNet
will warn you those iterations are short; for publishing official numbers
(e.g. for a release notes comparison), drop the flags and let BDN pick
its defaults — but expect each run to take 5–15 minutes.

## Future work

- **Per-PR benchmark regression gate.** Tracked in
  [KNOWN-GAPS.md](../KNOWN-GAPS.md). Will compare against a pinned
  `benchmarks/baseline.json` per OS+TFM.
- **Per-release benchmark table** in `CHANGELOG.md` so adopters can see
  the perf delta at a glance.
