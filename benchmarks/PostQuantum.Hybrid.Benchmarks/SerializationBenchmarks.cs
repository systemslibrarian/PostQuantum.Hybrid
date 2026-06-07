using BenchmarkDotNet.Attributes;
using PostQuantum.Hybrid;

namespace PostQuantum.Hybrid.Benchmarks;

[MemoryDiagnoser]
public class SerializationBenchmarks
{
    private HybridKemKeyPair _kemPair = null!;
    private HybridSignatureKeyPair _sigPair = null!;
    private byte[] _kemPubBytes = null!;
    private byte[] _kemPrivBytes = null!;
    private string _kemPubPem = null!;
    private byte[] _sigPubBytes = null!;
    private string _sigPubPem = null!;

    [GlobalSetup]
    public void Setup()
    {
        _kemPair = HybridKem.GenerateKeyPair();
        _sigPair = HybridSignature.GenerateKeyPair();
        _kemPubBytes = _kemPair.PublicKey.Export();
        _kemPrivBytes = _kemPair.PrivateKey.Export();
        _kemPubPem = _kemPair.PublicKey.ExportPem();
        _sigPubBytes = _sigPair.PublicKey.Export();
        _sigPubPem = _sigPair.PublicKey.ExportPem();
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _kemPair.Dispose();
        _sigPair.Dispose();
    }

    [Benchmark] public byte[] KemPubKey_Export() => _kemPair.PublicKey.Export();
    [Benchmark] public HybridKemPublicKey KemPubKey_Import() => HybridKemPublicKey.Import(_kemPubBytes);
    [Benchmark] public string KemPubKey_ExportPem() => _kemPair.PublicKey.ExportPem();
    [Benchmark] public HybridKemPublicKey KemPubKey_ImportPem() => HybridKemPublicKey.ImportPem(_kemPubPem);

    [Benchmark] public byte[] KemPrivKey_Export() => _kemPair.PrivateKey.Export();
    [Benchmark]
    public void KemPrivKey_Import()
    {
        using var k = HybridKemPrivateKey.Import(_kemPrivBytes);
    }

    [Benchmark] public byte[] SigPubKey_Export() => _sigPair.PublicKey.Export();
    [Benchmark] public HybridSignaturePublicKey SigPubKey_Import() => HybridSignaturePublicKey.Import(_sigPubBytes);
    [Benchmark] public string SigPubKey_ExportPem() => _sigPair.PublicKey.ExportPem();
    [Benchmark] public HybridSignaturePublicKey SigPubKey_ImportPem() => HybridSignaturePublicKey.ImportPem(_sigPubPem);
}
