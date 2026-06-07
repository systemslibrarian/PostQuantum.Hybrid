using BenchmarkDotNet.Attributes;
using PostQuantum.Hybrid;

namespace PostQuantum.Hybrid.Benchmarks;

[MemoryDiagnoser]
public class HybridKemBenchmarks
{
    private HybridKemKeyPair _keyPair = null!;
    private HybridKemPublicKey _publicKey = null!;
    private HybridKemCiphertext _ciphertext = null!;

    [GlobalSetup]
    public void Setup()
    {
        _keyPair = HybridKem.GenerateKeyPair();
        _publicKey = _keyPair.PublicKey;
        using var enc = HybridKem.Encapsulate(_publicKey);
        _ciphertext = enc.Ciphertext;
    }

    [GlobalCleanup]
    public void Cleanup() => _keyPair.Dispose();

    [Benchmark(Description = "GenerateKeyPair")]
    public HybridKemKeyPair GenerateKeyPair()
    {
        var pair = HybridKem.GenerateKeyPair();
        pair.Dispose();
        return pair;
    }

    [Benchmark(Description = "Encapsulate")]
    public byte[] Encapsulate()
    {
        using var enc = HybridKem.Encapsulate(_publicKey);
        return enc.SharedSecret;
    }

    [Benchmark(Description = "Decapsulate")]
    public byte[] Decapsulate() => HybridKem.Decapsulate(_keyPair.PrivateKey, _ciphertext);
}
