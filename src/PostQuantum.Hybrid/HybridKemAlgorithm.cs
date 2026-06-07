namespace PostQuantum.Hybrid;

/// <summary>
/// Identifies the algorithm combination used by a hybrid KEM construction.
/// </summary>
public enum HybridKemAlgorithm
{
    /// <summary>
    /// X25519 + ML-KEM-768 with the HKDF-SHA256 transcript-binding combiner
    /// (see ADR 0003). Recommended default for v1.0 production use.
    /// ~128-bit classical / NIST Level 3 PQ security.
    /// </summary>
    X25519MlKem768 = 1,

    /// <summary>
    /// **Preview.** X25519 + ML-KEM-768 with the X-Wing-style SHA3-256
    /// combiner (see ADR 0013). Uses the same per-component wire layout
    /// as <see cref="X25519MlKem768"/> — only the algorithm-id byte and
    /// the combiner formula differ. Provided so callers can opt in to a
    /// formally-analyzed combiner; subject to refinement before v2.
    /// </summary>
    X25519MlKem768XWing = 2,
}
