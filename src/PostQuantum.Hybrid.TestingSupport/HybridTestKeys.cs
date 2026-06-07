namespace PostQuantum.Hybrid.TestingSupport;

/// <summary>
/// Lazily-initialized, process-wide test key pairs. Cuts repeated
/// keygen cost when many tests need <em>a</em> hybrid key pair but
/// don't care which one.
/// </summary>
public static class HybridTestKeys
{
    private static readonly Lazy<HybridKemKeyPair> _kemPair =
        new(HybridKem.GenerateKeyPair, isThreadSafe: true);

    private static readonly Lazy<HybridSignatureKeyPair> _sigPair =
        new(HybridSignature.GenerateKeyPair, isThreadSafe: true);

    /// <summary>
    /// A shared hybrid KEM key pair generated once per process. Safe
    /// to share across parallel tests; do NOT dispose.
    /// </summary>
    public static HybridKemKeyPair SharedKemPair => _kemPair.Value;

    /// <summary>
    /// A shared hybrid signature key pair generated once per process.
    /// Safe to share across parallel tests; do NOT dispose.
    /// </summary>
    public static HybridSignatureKeyPair SharedSignaturePair => _sigPair.Value;

    /// <summary>Generate a fresh hybrid KEM key pair for an isolated test.</summary>
    public static HybridKemKeyPair GenerateFreshKemKeyPair() => HybridKem.GenerateKeyPair();

    /// <summary>Generate a fresh hybrid signature key pair for an isolated test.</summary>
    public static HybridSignatureKeyPair GenerateFreshSignatureKeyPair() => HybridSignature.GenerateKeyPair();
}
