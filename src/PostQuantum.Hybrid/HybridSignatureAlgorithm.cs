namespace PostQuantum.Hybrid;

/// <summary>
/// Identifies the algorithm combination used by a hybrid digital-signature construction.
/// </summary>
public enum HybridSignatureAlgorithm
{
    /// <summary>
    /// Ed25519 + ML-DSA-65. Recommended default. ~128-bit classical / NIST Level 3 PQ security.
    /// </summary>
    Ed25519MlDsa65 = 1,
}
