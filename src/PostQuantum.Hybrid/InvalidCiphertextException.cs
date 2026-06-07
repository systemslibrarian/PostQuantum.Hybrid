namespace PostQuantum.Hybrid;

/// <summary>
/// Thrown when a hybrid KEM ciphertext blob cannot be parsed or accepted.
/// Common reasons (via <see cref="PostQuantumHybridException.Reason"/>):
/// <see cref="HybridFailureReason.InvalidLength"/>,
/// <see cref="HybridFailureReason.UnsupportedAlgorithmId"/>, and
/// <see cref="HybridFailureReason.AlgorithmMismatch"/> (the ciphertext's
/// algorithm id differs from the private key it is presented against).
/// </summary>
/// <remarks>
/// Implicit-rejection failures (FIPS 203) do <em>not</em> throw this:
/// they yield a pseudorandom secret instead, and downstream AEAD
/// decryption fails authentically. This exception only covers wire-shape
/// problems that we can detect cheaply before reaching the primitive.
/// </remarks>
public sealed class InvalidCiphertextException : PostQuantumHybridException
{
    /// <summary>Constructs a new exception with the given reason and message.</summary>
    public InvalidCiphertextException(HybridFailureReason reason, string message)
        : base(reason, message)
    {
    }

    /// <summary>Constructs a new exception with the given reason, message, and inner exception.</summary>
    public InvalidCiphertextException(HybridFailureReason reason, string message, Exception innerException)
        : base(reason, message, innerException)
    {
    }
}
