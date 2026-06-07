using System.Security.Cryptography;

namespace PostQuantum.Hybrid;

/// <summary>
/// The reason a <see cref="PostQuantumHybridException"/> was thrown.
/// New values will only be added in minor releases; values are stable.
/// </summary>
public enum HybridFailureReason
{
    /// <summary>Unclassified failure. Inspect <see cref="Exception.Message"/>.</summary>
    Unknown = 0,

    /// <summary>The serialized blob is not the expected length for its type.</summary>
    InvalidLength = 1,

    /// <summary>The first byte (algorithm identifier) is not in the supported set.</summary>
    UnsupportedAlgorithmId = 2,

    /// <summary>
    /// Two artifacts that must belong to the same algorithm combination
    /// (e.g. a private key and a ciphertext) carry different algorithm ids.
    /// </summary>
    AlgorithmMismatch = 3,

    /// <summary>
    /// The runtime does not expose the underlying post-quantum primitive
    /// (e.g. .NET 10 native ML-KEM requires a recent enough host crypto stack).
    /// </summary>
    PrimitiveNotSupported = 4,
}

/// <summary>
/// Thrown by PostQuantum.Hybrid when a cryptographic operation fails for a
/// reason the library can describe categorically. Inherits from
/// <see cref="CryptographicException"/> so callers that catch the latter
/// continue to work without changes.
/// </summary>
public class PostQuantumHybridException : CryptographicException
{
    /// <summary>The categorical reason for the failure.</summary>
    public HybridFailureReason Reason { get; }

    /// <summary>Constructs a new exception with the given reason and message.</summary>
    public PostQuantumHybridException(HybridFailureReason reason, string message)
        : base(message)
    {
        Reason = reason;
    }

    /// <summary>Constructs a new exception with the given reason, message, and inner exception.</summary>
    public PostQuantumHybridException(HybridFailureReason reason, string message, Exception innerException)
        : base(message, innerException)
    {
        Reason = reason;
    }
}
