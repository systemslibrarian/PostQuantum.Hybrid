namespace PostQuantum.Hybrid.TestingSupport;

/// <summary>
/// Minimal in-memory key provider for tests that want to wire through
/// the <c>PostQuantum.Hybrid.AspNetCore</c> abstractions without
/// instantiating a real host or reading PEM files. Implements the
/// same shape as <c>IHybridKemKeyProvider</c> without taking a
/// dependency on that package, by exposing matching property names.
/// </summary>
/// <remarks>
/// To use with the real <c>IHybridKemKeyProvider</c> contract, write
/// a thin adapter in the consuming test project — or reference
/// <c>PostQuantum.Hybrid.AspNetCore</c> directly. This package
/// deliberately does not depend on AspNetCore to keep the dependency
/// graph minimal.
/// </remarks>
public sealed class FakeHybridKemKeyProvider : IDisposable
{
    public HybridKemPublicKey PublicKey { get; }
    public HybridKemPrivateKey PrivateKey { get; }

    public FakeHybridKemKeyProvider(HybridKemKeyPair pair)
    {
        ArgumentNullException.ThrowIfNull(pair);
        PublicKey = pair.PublicKey;
        PrivateKey = pair.PrivateKey;
    }

    public FakeHybridKemKeyProvider()
        : this(HybridKem.GenerateKeyPair())
    { }

    public void Dispose() => PrivateKey.Dispose();
}

/// <summary>
/// Minimal in-memory signature key provider for tests. Same shape as
/// <c>IHybridSignatureKeyProvider</c>.
/// </summary>
public sealed class FakeHybridSignatureKeyProvider : IDisposable
{
    public HybridSignaturePublicKey PublicKey { get; }
    public HybridSignaturePrivateKey PrivateKey { get; }

    public FakeHybridSignatureKeyProvider(HybridSignatureKeyPair pair)
    {
        ArgumentNullException.ThrowIfNull(pair);
        PublicKey = pair.PublicKey;
        PrivateKey = pair.PrivateKey;
    }

    public FakeHybridSignatureKeyProvider()
        : this(HybridSignature.GenerateKeyPair())
    { }

    public void Dispose() => PrivateKey.Dispose();
}
