using Microsoft.AspNetCore.DataProtection;

namespace PostQuantum.Hybrid.AspNetCore;

/// <summary>
/// Adapts <see cref="IHybridKemKeyProvider"/> to ASP.NET Core's
/// <see cref="IDataProtector"/> contract. Each protected payload is
/// sealed using the recipient's KEM public key via the envelope
/// construction shipped in <c>PostQuantum.Hybrid.Envelopes</c>; each
/// unprotect uses the matching private key.
/// </summary>
/// <remarks>
/// This adapter exists so callers already plumbed through the standard
/// <see cref="IDataProtector"/> interface can opt in to hybrid PQ
/// confidentiality without rewriting the calling code. To avoid taking
/// a hard dependency on <c>PostQuantum.Hybrid.Envelopes</c>, the
/// seal/open logic is implemented locally and mirrors the wire format
/// the Envelopes package uses. Both wire formats are stable; consumers
/// using either path can interop.
/// </remarks>
public sealed class HybridEnvelopeDataProtector : IDataProtector
{
    private readonly IHybridKemKeyProvider _keyProvider;
    private readonly string _purpose;

    /// <summary>Construct a protector bound to the given purpose chain.</summary>
    public HybridEnvelopeDataProtector(IHybridKemKeyProvider keyProvider, string purpose)
    {
        _keyProvider = keyProvider ?? throw new ArgumentNullException(nameof(keyProvider));
        _purpose = purpose ?? throw new ArgumentNullException(nameof(purpose));
    }

    /// <inheritdoc />
    public IDataProtector CreateProtector(string purpose) =>
        new HybridEnvelopeDataProtector(_keyProvider, _purpose + "." + (purpose ?? string.Empty));

    /// <inheritdoc />
    public byte[] Protect(byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        return EnvelopeFormat.Seal(_keyProvider.PublicKey, plaintext, _purpose);
    }

    /// <inheritdoc />
    public byte[] Unprotect(byte[] protectedData)
    {
        ArgumentNullException.ThrowIfNull(protectedData);
        return EnvelopeFormat.Open(_keyProvider.PrivateKey, protectedData, _purpose);
    }
}
