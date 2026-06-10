namespace PostQuantum.Hybrid.TestingSupport;

/// <summary>
/// Minimal in-memory key provider for tests that want to wire through
/// the <c>PostQuantum.Hybrid.AspNetCore</c> abstractions without
/// instantiating a real host or reading PEM files. Implements the
/// same shape as <c>IHybridKemKeyProvider</c> without taking a
/// dependency on that package, by exposing matching property names.
/// </summary>
/// <remarks>
/// <para>To use with the real <c>IHybridKemKeyProvider</c> contract, write
/// a thin adapter in the consuming test project — or reference
/// <c>PostQuantum.Hybrid.AspNetCore</c> directly. This package
/// deliberately does not depend on AspNetCore to keep the dependency
/// graph minimal.</para>
/// <para><b>Ownership.</b> <see cref="Dispose"/> only disposes the
/// underlying key pair when this provider <em>generated</em> it (the
/// parameterless constructor). When a key pair is passed in via the
/// <see cref="FakeHybridKemKeyProvider(HybridKemKeyPair)"/> constructor,
/// ownership stays with the caller and <see cref="Dispose"/> is a no-op
/// for the keys — important when the caller wraps
/// <see cref="HybridTestKeys.SharedKemPair"/>, which must outlive any
/// single test.</para>
/// </remarks>
public sealed class FakeHybridKemKeyProvider : IDisposable
{
    private readonly HybridKemKeyPair? _ownedPair;

    public HybridKemPublicKey PublicKey { get; }
    public HybridKemPrivateKey PrivateKey { get; }

    public FakeHybridKemKeyProvider(HybridKemKeyPair pair)
    {
        ArgumentNullException.ThrowIfNull(pair);
        PublicKey = pair.PublicKey;
        PrivateKey = pair.PrivateKey;
        // _ownedPair stays null — caller retains ownership of pair.
    }

    public FakeHybridKemKeyProvider()
    {
        _ownedPair = HybridKem.GenerateKeyPair();
        PublicKey = _ownedPair.PublicKey;
        PrivateKey = _ownedPair.PrivateKey;
    }

    public void Dispose() => _ownedPair?.Dispose();
}

/// <summary>
/// Minimal in-memory signature key provider for tests. Same shape as
/// <c>IHybridSignatureKeyProvider</c>.
/// </summary>
/// <remarks>
/// <para><b>Ownership.</b> <see cref="Dispose"/> only disposes the
/// underlying key pair when this provider generated it. When a key pair
/// is passed in via
/// <see cref="FakeHybridSignatureKeyProvider(HybridSignatureKeyPair)"/>,
/// ownership stays with the caller.</para>
/// </remarks>
public sealed class FakeHybridSignatureKeyProvider : IDisposable
{
    private readonly HybridSignatureKeyPair? _ownedPair;

    public HybridSignaturePublicKey PublicKey { get; }
    public HybridSignaturePrivateKey PrivateKey { get; }

    public FakeHybridSignatureKeyProvider(HybridSignatureKeyPair pair)
    {
        ArgumentNullException.ThrowIfNull(pair);
        PublicKey = pair.PublicKey;
        PrivateKey = pair.PrivateKey;
        // _ownedPair stays null — caller retains ownership of pair.
    }

    public FakeHybridSignatureKeyProvider()
    {
        _ownedPair = HybridSignature.GenerateKeyPair();
        PublicKey = _ownedPair.PublicKey;
        PrivateKey = _ownedPair.PrivateKey;
    }

    public void Dispose() => _ownedPair?.Dispose();
}
