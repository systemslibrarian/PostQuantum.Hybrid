namespace PostQuantum.Hybrid;

/// <summary>
/// Thrown when a hybrid key blob (public or private, KEM or signature)
/// cannot be parsed from its wire-format bytes. Inspect
/// <see cref="PostQuantumHybridException.Reason"/> for the precise cause;
/// the common values are <see cref="HybridFailureReason.InvalidLength"/>
/// and <see cref="HybridFailureReason.UnsupportedAlgorithmId"/>.
/// </summary>
/// <remarks>
/// This is a typed subclass of <see cref="PostQuantumHybridException"/>.
/// Callers that prefer the categorical enum can continue to catch the
/// base class; callers that prefer typed <c>catch</c> blocks can target
/// <c>HybridKeyParseException</c> directly. Both styles work — pick the
/// one that fits the call site.
/// </remarks>
public sealed class HybridKeyParseException : PostQuantumHybridException
{
    /// <summary>Constructs a new exception with the given reason and message.</summary>
    public HybridKeyParseException(HybridFailureReason reason, string message)
        : base(reason, message)
    {
    }

    /// <summary>Constructs a new exception with the given reason, message, and inner exception.</summary>
    public HybridKeyParseException(HybridFailureReason reason, string message, Exception innerException)
        : base(reason, message, innerException)
    {
    }
}
