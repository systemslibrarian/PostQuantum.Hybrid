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

    /// <summary>
    /// **Preview.** Strict IETF X-Wing per
    /// <see href="https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/">
    /// draft-connolly-cfrg-xwing-kem-10</see> (see ADR 0015). Byte-for-byte
    /// interoperable with other X-Wing implementations once the 1-byte
    /// algorithm-id prefix is stripped: post-quantum-first component order
    /// (<c>pk_M || pk_X</c>, <c>ct_M || ct_X</c>) and a 32-byte seed as the
    /// entire decapsulation key. Preview until the draft becomes an RFC; if
    /// a later draft changes the scheme, a new algorithm-id will be
    /// allocated rather than mutating this one.
    /// </summary>
    XWing = 3,
}
