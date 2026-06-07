namespace PostQuantum.Hybrid.AspNetCore;

/// <summary>
/// Strongly-typed configuration for the <c>AddPostQuantumHybrid</c> extensions.
/// For each key family (KEM and signature), supply both the public-key
/// and private-key PEM (inline OR a file path; inline wins when both are
/// supplied). Either family may be omitted entirely — the corresponding
/// key provider will throw on first use if so.
/// </summary>
public sealed class HybridCryptoOptions
{
    /// <summary>Inline PEM for the hybrid KEM public key.</summary>
    public string? KemPublicKeyPem { get; set; }

    /// <summary>Path to a PEM file containing the hybrid KEM public key.</summary>
    public string? KemPublicKeyPath { get; set; }

    /// <summary>Inline PEM for the hybrid KEM private key.</summary>
    public string? KemPrivateKeyPem { get; set; }

    /// <summary>Path to a PEM file containing the hybrid KEM private key.</summary>
    public string? KemPrivateKeyPath { get; set; }

    /// <summary>Inline PEM for the hybrid signature public key.</summary>
    public string? SignaturePublicKeyPem { get; set; }

    /// <summary>Path to a PEM file containing the hybrid signature public key.</summary>
    public string? SignaturePublicKeyPath { get; set; }

    /// <summary>Inline PEM for the hybrid signature private key.</summary>
    public string? SignaturePrivateKeyPem { get; set; }

    /// <summary>Path to a PEM file containing the hybrid signature private key.</summary>
    public string? SignaturePrivateKeyPath { get; set; }
}
