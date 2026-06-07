```

BenchmarkDotNet v0.15.8, Windows 11 (10.0.26200.8457/25H2/2025Update/HudsonValley2)
Intel Core Ultra 7 256V 2.20GHz, 1 CPU, 8 logical and 8 physical cores
.NET SDK 10.0.300
  [Host]     : .NET 8.0.27 (8.0.27, 8.0.2726.22922), X64 RyuJIT x86-64-v3
  Job-VBCXOY : .NET 8.0.27 (8.0.27, 8.0.2726.22922), X64 RyuJIT x86-64-v3

InvocationCount=16  IterationCount=3  WarmupCount=2  

```
| Method | MessageSize | Mean     | Error      | StdDev    | Allocated |
|------- |------------ |---------:|-----------:|----------:|----------:|
| **Sign**   | **64**          | **4.169 ms** | **18.6602 ms** | **1.0228 ms** | **640.27 KB** |
| Verify | 64          | 1.144 ms |  0.5291 ms | 0.0290 ms | 189.12 KB |
| **Sign**   | **1024**        | **5.027 ms** |  **8.9863 ms** | **0.4926 ms** | **587.09 KB** |
| Verify | 1024        | 1.234 ms |  0.1894 ms | 0.0104 ms |  190.8 KB |
| **Sign**   | **65536**       | **5.109 ms** | **19.7874 ms** | **1.0846 ms** |  **775.8 KB** |
| Verify | 65536       | 2.729 ms |  1.5926 ms | 0.0873 ms |  316.8 KB |
