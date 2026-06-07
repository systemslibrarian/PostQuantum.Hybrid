using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;

namespace PostQuantum.Hybrid.Internal;

/// <summary>
/// Registry + facade for hybrid KEM combiners.
/// </summary>
internal static class KemCombiner
{
    /// <summary>Returns the combiner implementation for the given algorithm-id.</summary>
    public static IKemCombiner ForAlgorithm(HybridKemAlgorithm algorithm) => algorithm switch
    {
        HybridKemAlgorithm.X25519MlKem768      => HkdfTranscriptKemCombiner.Instance,
        HybridKemAlgorithm.X25519MlKem768XWing => XWingKemCombiner.Instance,
        _ => throw new PostQuantumHybridException(
            HybridFailureReason.UnsupportedAlgorithmId,
            $"No KEM combiner registered for algorithm: {algorithm}."),
    };

    /// <summary>
    /// Convenience for the v1 default combiner. Allocates a fresh 32-byte
    /// array. Hot paths should prefer
    /// <see cref="ForAlgorithm"/> + a caller-owned span.
    /// </summary>
    public static byte[] Combine(
        ReadOnlySpan<byte> classicalSecret,
        ReadOnlySpan<byte> pqSecret,
        ReadOnlySpan<byte> classicalCiphertext,
        ReadOnlySpan<byte> pqCiphertext,
        ReadOnlySpan<byte> recipientClassicalPublicKey)
    {
        var output = new byte[AlgorithmSizes.HybridSharedSecretBytes];
        HkdfTranscriptKemCombiner.Instance.Combine(
            classicalSecret, pqSecret, classicalCiphertext, pqCiphertext,
            recipientClassicalPublicKey, output);
        return output;
    }
}

/// <summary>
/// The v1 default combiner: HKDF-SHA256 with the two component shared
/// secrets concatenated as IKM and both ciphertexts bound into the info
/// parameter so the derived secret depends on the full transcript.
/// See <see href="../../../docs/adr/0003-kem-combiner.md">ADR 0003</see>.
/// Does not use the recipient public key; that parameter is accepted
/// only to satisfy the <see cref="IKemCombiner"/> contract.
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
        ReadOnlySpan<byte> recipientClassicalPublicKey,
        Span<byte> output)
    {
        _ = recipientClassicalPublicKey; // unused by this combiner
        if (output.Length != AlgorithmSizes.HybridSharedSecretBytes)
        {
            throw new ArgumentException(
                $"output must be {AlgorithmSizes.HybridSharedSecretBytes} bytes.",
                nameof(output));
        }

        Span<byte> ikm = stackalloc byte[classicalSecret.Length + pqSecret.Length];
        classicalSecret.CopyTo(ikm);
        pqSecret.CopyTo(ikm[classicalSecret.Length..]);

        byte[] info = new byte[InfoPrefix.Length + classicalCiphertext.Length + pqCiphertext.Length];
        InfoPrefix.CopyTo(info, 0);
        classicalCiphertext.CopyTo(info.AsSpan(InfoPrefix.Length));
        pqCiphertext.CopyTo(info.AsSpan(InfoPrefix.Length + classicalCiphertext.Length));

        HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, output, salt: default, info: info);
        CryptographicOperations.ZeroMemory(ikm);
    }
}

/// <summary>
/// X-Wing-style SHA3-256 combiner, per the
/// <see href="https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/">
/// draft-connolly-cfrg-xwing-kem</see> formula:
/// <code>
/// SS = SHA3-256( label6 || ss_M || ss_X || ct_X || pk_X )
/// </code>
/// where <c>label6</c> is the 6-byte fixed prefix from the draft,
/// <c>ss_M</c> is the ML-KEM-768 shared secret, <c>ss_X</c> is the X25519
/// shared secret, <c>ct_X</c> is the X25519 "ciphertext" (the sender's
/// ephemeral public key), and <c>pk_X</c> is the recipient's X25519
/// public key.
/// </summary>
/// <remarks>
/// <para><b>This implementation is NOT byte-compatible with the IETF
/// X-Wing wire format.</b> PostQuantum.Hybrid v1 keeps the
/// classical-first component ordering for both KEM keys and KEM
/// ciphertexts at every algorithm-id; the IETF X-Wing draft uses
/// post-quantum-first ordering. Algorithm-id <c>0x02</c> therefore
/// represents "the X-Wing combiner applied to PostQuantum.Hybrid's
/// v1 wire shape," not strict X-Wing interop. See ADR 0013 for the
/// rationale.</para>
/// <para>SHA3-256 is provided by BouncyCastle so the combiner has
/// identical behavior on every TFM and host platform — the BCL
/// <see cref="SHA3_256"/> requires Windows 11 24H2 or an OpenSSL
/// build with SHA3, which we cannot rely on across the support
/// matrix.</para>
/// </remarks>
internal sealed class XWingKemCombiner : IKemCombiner
{
    public static IKemCombiner Instance { get; } = new XWingKemCombiner();

    /// <summary>
    /// The 6-byte fixed label from draft-connolly-cfrg-xwing-kem section 5.
    /// </summary>
    private static readonly byte[] Label = { 0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c };

    public void Combine(
        ReadOnlySpan<byte> classicalSecret,
        ReadOnlySpan<byte> pqSecret,
        ReadOnlySpan<byte> classicalCiphertext,
        ReadOnlySpan<byte> pqCiphertext,
        ReadOnlySpan<byte> recipientClassicalPublicKey,
        Span<byte> output)
    {
        _ = pqCiphertext; // X-Wing's combiner does not bind ct_M directly; ss_M depends on it.
        if (output.Length != AlgorithmSizes.HybridSharedSecretBytes)
        {
            throw new ArgumentException(
                $"output must be {AlgorithmSizes.HybridSharedSecretBytes} bytes.",
                nameof(output));
        }
        if (recipientClassicalPublicKey.Length != AlgorithmSizes.X25519PublicKeyBytes)
        {
            throw new ArgumentException(
                $"recipientClassicalPublicKey must be {AlgorithmSizes.X25519PublicKeyBytes} bytes.",
                nameof(recipientClassicalPublicKey));
        }

        var sha3 = new Sha3Digest(256);
        sha3.BlockUpdate(Label, 0, Label.Length);
        // ss_M (ML-KEM shared secret)
        var pqBuf = pqSecret.ToArray();
        sha3.BlockUpdate(pqBuf, 0, pqBuf.Length);
        CryptographicOperations.ZeroMemory(pqBuf);
        // ss_X (X25519 shared secret)
        var clBuf = classicalSecret.ToArray();
        sha3.BlockUpdate(clBuf, 0, clBuf.Length);
        CryptographicOperations.ZeroMemory(clBuf);
        // ct_X (sender's ephemeral X25519 public)
        var ctBuf = classicalCiphertext.ToArray();
        sha3.BlockUpdate(ctBuf, 0, ctBuf.Length);
        // pk_X (recipient's X25519 public)
        var pkBuf = recipientClassicalPublicKey.ToArray();
        sha3.BlockUpdate(pkBuf, 0, pkBuf.Length);

        var digest = new byte[AlgorithmSizes.HybridSharedSecretBytes];
        sha3.DoFinal(digest, 0);
        digest.CopyTo(output);
        CryptographicOperations.ZeroMemory(digest);
    }
}
