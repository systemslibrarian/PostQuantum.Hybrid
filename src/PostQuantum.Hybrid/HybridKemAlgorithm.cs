namespace PostQuantum.Hybrid;

/// <summary>
/// Identifies the algorithm combination used by a hybrid KEM construction.
/// </summary>
public enum HybridKemAlgorithm
{
    /// <summary>
    /// X25519 + ML-KEM-768. Recommended default. ~128-bit classical / NIST Level 3 PQ security.
    /// </summary>
    X25519MlKem768 = 1,
}
