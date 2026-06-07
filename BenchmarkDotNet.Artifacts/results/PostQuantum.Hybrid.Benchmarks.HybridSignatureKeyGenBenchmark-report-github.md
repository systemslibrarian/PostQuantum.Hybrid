```

BenchmarkDotNet v0.15.8, Windows 11 (10.0.26200.8457/25H2/2025Update/HudsonValley2)
Intel Core Ultra 7 256V 2.20GHz, 1 CPU, 8 logical and 8 physical cores
.NET SDK 10.0.300
  [Host]     : .NET 10.0.8 (10.0.8, 10.0.826.23019), X64 RyuJIT x86-64-v3
  Job-VBCXOY : .NET 10.0.8 (10.0.8, 10.0.826.23019), X64 RyuJIT x86-64-v3

InvocationCount=16  IterationCount=3  WarmupCount=2  

```
| Method          | Mean     | Error    | StdDev    | Allocated |
|---------------- |---------:|---------:|----------:|----------:|
| GenerateKeyPair | 1.803 ms | 3.523 ms | 0.1931 ms |   9.53 KB |
