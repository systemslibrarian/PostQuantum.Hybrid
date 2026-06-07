namespace PostQuantum.Hybrid.Internal;

/// <summary>
/// Combines the two component shared secrets of a hybrid KEM exchange
/// into a single derived secret. Implementations choose the KDF and the
/// transcript binding; the contract is just "given the inputs and a
/// destination span, fill the span deterministically."
/// </summary>
/// <remarks>
/// The seam exists so multiple combiners can coexist:
/// <see cref="HkdfTranscriptKemCombiner"/> backs algorithm-id <c>0x01</c>;
/// <see cref="XWingKemCombiner"/> backs algorithm-id <c>0x02</c>.
/// <see cref="KemCombiner.ForAlgorithm"/> is the dispatch registry.
/// </remarks>
internal interface IKemCombiner
{
    /// <summary>
    /// Combine the inputs and write the derived secret into
    /// <paramref name="output"/>. The output span must be exactly
    /// <see cref="AlgorithmSizes.HybridSharedSecretBytes"/> bytes long.
    /// </summary>
    /// <param name="classicalSecret">The classical (X25519) shared secret.</param>
    /// <param name="pqSecret">The post-quantum (ML-KEM) shared secret.</param>
    /// <param name="classicalCiphertext">The classical "ciphertext" — for X25519 this is the sender's ephemeral public key.</param>
    /// <param name="pqCiphertext">The post-quantum ciphertext (ML-KEM ct).</param>
    /// <param name="recipientClassicalPublicKey">
    ///   The recipient's classical public key. The HKDF combiner ignores
    ///   this; the X-Wing combiner binds it into the SHA3 input per the
    ///   draft-connolly-cfrg-xwing-kem specification.
    /// </param>
    /// <param name="output">Destination for the 32-byte combined secret.</param>
    void Combine(
        ReadOnlySpan<byte> classicalSecret,
        ReadOnlySpan<byte> pqSecret,
        ReadOnlySpan<byte> classicalCiphertext,
        ReadOnlySpan<byte> pqCiphertext,
        ReadOnlySpan<byte> recipientClassicalPublicKey,
        Span<byte> output);
}
