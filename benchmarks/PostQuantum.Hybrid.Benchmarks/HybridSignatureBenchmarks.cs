using BenchmarkDotNet.Attributes;
using PostQuantum.Hybrid;

namespace PostQuantum.Hybrid.Benchmarks;

[MemoryDiagnoser]
public class HybridSignatureBenchmarks
{
    private HybridSignatureKeyPair _keyPair = null!;
    private byte[] _message = null!;
    private byte[] _signature = null!;

    [Params(64, 1024, 65536)]
    public int MessageSize { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _keyPair = HybridSignature.GenerateKeyPair();
        _message = new byte[MessageSize];
        new Random(42).NextBytes(_message);
        _signature = HybridSignature.Sign(_keyPair.PrivateKey, _message);
    }

    [GlobalCleanup]
    public void Cleanup() => _keyPair.Dispose();

    [Benchmark(Description = "Sign")]
    public byte[] Sign() => HybridSignature.Sign(_keyPair.PrivateKey, _message);

    [Benchmark(Description = "Verify")]
    public bool Verify() => HybridSignature.Verify(_keyPair.PublicKey, _message, _signature);
}

[MemoryDiagnoser]
public class HybridSignatureKeyGenBenchmark
{
    [Benchmark(Description = "GenerateKeyPair")]
    public HybridSignatureKeyPair GenerateKeyPair()
    {
        var pair = HybridSignature.GenerateKeyPair();
        pair.Dispose();
        return pair;
    }
}
