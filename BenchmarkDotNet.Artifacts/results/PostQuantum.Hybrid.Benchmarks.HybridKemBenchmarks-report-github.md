```

BenchmarkDotNet v0.15.8, Windows 11 (10.0.26200.8457/25H2/2025Update/HudsonValley2)
Intel Core Ultra 7 256V 2.20GHz, 1 CPU, 8 logical and 8 physical cores
.NET SDK 10.0.300
  [Host]     : .NET 8.0.27 (8.0.27, 8.0.2726.22922), X64 RyuJIT x86-64-v3
  Job-VBCXOY : .NET 8.0.27 (8.0.27, 8.0.2726.22922), X64 RyuJIT x86-64-v3

InvocationCount=16  IterationCount=3  WarmupCount=2  

```
| Method          | Mean     | Error    | StdDev   | Allocated |
|---------------- |---------:|---------:|---------:|----------:|
| GenerateKeyPair | 590.5 μs | 274.7 μs | 15.05 μs |  29.24 KB |
| Encapsulate     | 977.6 μs | 505.0 μs | 27.68 μs |  35.69 KB |
| Decapsulate     | 861.3 μs | 751.6 μs | 41.20 μs |  39.92 KB |
