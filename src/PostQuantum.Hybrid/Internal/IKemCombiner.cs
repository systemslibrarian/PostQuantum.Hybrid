namespace PostQuantum.Hybrid.Internal;

/// <summary>
/// Combines the two component shared secrets of a hybrid KEM exchange
/// into a single derived secret. Implementations choose the KDF and the
/// transcript binding; the contract is just "given the four inputs and a
/// destination span, fill the span deterministically."
/// </summary>
/// <remarks>
/// The seam exists so future combiners (X-Wing under algorithm-id
/// <c>0x02</c>, for example) can be plugged in without modifying
/// <see cref="HybridKem"/>. See <see cref="KemCombiner.ForAlgorithm"/>
/// for the registry.
/// </remarks>
internal interface IKemCombiner
{
    /// <summary>
    /// Combine the inputs and write the derived secret into
    /// <paramref name="output"/>. The output span must be exactly
    /// <see cref="AlgorithmSizes.HybridSharedSecretBytes"/> bytes long.
    /// </summary>
    void Combine(
        ReadOnlySpan<byte> classicalSecret,
        ReadOnlySpan<byte> pqSecret,
        ReadOnlySpan<byte> classicalCiphertext,
        ReadOnlySpan<byte> pqCiphertext,
        Span<byte> output);
}
