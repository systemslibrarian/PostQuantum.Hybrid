using System.Security.Cryptography;
using System.Text;

namespace PostQuantum.Hybrid.Internal;

/// <summary>
/// Registry + facade for hybrid KEM combiners. Calls
/// <see cref="ForAlgorithm"/> to get the <see cref="IKemCombiner"/>
/// implementation that matches a given algorithm-id, or the
/// <see cref="Combine"/> static helper for v1's single combiner.
/// </summary>
internal static class KemCombiner
{
    /// <summary>Returns the combiner implementation for the given algorithm-id.</summary>
    public static IKemCombiner ForAlgorithm(HybridKemAlgorithm algorithm) => algorithm switch
    {
        HybridKemAlgorithm.X25519MlKem768 => HkdfTranscriptKemCombiner.Instance,
        _ => throw new PostQuantumHybridException(
            HybridFailureReason.UnsupportedAlgorithmId,
            $"No KEM combiner registered for algorithm: {algorithm}."),
    };

    /// <summary>
    /// Convenience: combine using the v1 default combiner (HKDF-SHA256 with
    /// transcript binding) and return a fresh 32-byte array. Allocates;
    /// for hot paths use <see cref="ForAlgorithm"/> and pass a caller-owned
    /// span as the output destination.
    /// </summary>
    public static byte[] Combine(
        ReadOnlySpan<byte> classicalSecret,
        ReadOnlySpan<byte> pqSecret,
        ReadOnlySpan<byte> classicalCiphertext,
        ReadOnlySpan<byte> pqCiphertext)
    {
        var output = new byte[AlgorithmSizes.HybridSharedSecretBytes];
        HkdfTranscriptKemCombiner.Instance.Combine(
            classicalSecret, pqSecret, classicalCiphertext, pqCiphertext, output);
        return output;
    }
}

/// <summary>
/// The v1 default combiner: HKDF-SHA256 with the two component shared
/// secrets concatenated as IKM and both ciphertexts bound into the info
/// parameter so the derived secret depends on the full transcript.
/// See <see href="../../../docs/adr/0003-kem-combiner.md">ADR 0003</see>.
/// </summary>
internal sealed class HkdfTranscriptKemCombiner : IKemCombiner
{
    public static IKemCombiner Instance { get; } = new HkdfTranscriptKemCombiner();

    private static readonly byte[] InfoPrefix =
        Encoding.ASCII.GetBytes("PostQuantum.Hybrid v1 KEM X25519-MLKEM768");

    public void Combine(
        ReadOnlySpan<byte> classicalSecret,
        ReadOnlySpan<byte> pqSecret,
        ReadOnlySpan<byte> classicalCiphertext,
        ReadOnlySpan<byte> pqCiphertext,
        Span<byte> output)
    {
        if (output.Length != AlgorithmSizes.HybridSharedSecretBytes)
        {
            throw new ArgumentException(
                $"output must be {AlgorithmSizes.HybridSharedSecretBytes} bytes.",
                nameof(output));
        }

        Span<byte> ikm = stackalloc byte[classicalSecret.Length + pqSecret.Length];
        classicalSecret.CopyTo(ikm);
        pqSecret.CopyTo(ikm[classicalSecret.Length..]);

        // info is small but variable-sized (depends on ciphertext lengths);
        // keep it heap-allocated to avoid stack-size surprises if a future
        // combiner accepts larger inputs.
        byte[] info = new byte[InfoPrefix.Length + classicalCiphertext.Length + pqCiphertext.Length];
        InfoPrefix.CopyTo(info, 0);
        classicalCiphertext.CopyTo(info.AsSpan(InfoPrefix.Length));
        pqCiphertext.CopyTo(info.AsSpan(InfoPrefix.Length + classicalCiphertext.Length));

        HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, output, salt: default, info: info);
        CryptographicOperations.ZeroMemory(ikm);
    }
}
