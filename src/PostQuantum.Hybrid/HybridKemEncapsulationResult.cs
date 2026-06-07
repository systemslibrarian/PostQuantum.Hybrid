using System.Diagnostics;
using System.Security.Cryptography;

namespace PostQuantum.Hybrid;

/// <summary>
/// The output of <see cref="HybridKem.Encapsulate"/>: a ciphertext to send to
/// the recipient and the 32-byte shared secret derived locally.
/// Dispose to clear the shared secret.
/// </summary>
[DebuggerDisplay("HybridKemEncapsulationResult (Ciphertext bytes; SharedSecret REDACTED)")]
public sealed class HybridKemEncapsulationResult : IDisposable
{
    private byte[] _sharedSecret;
    private bool _disposed;

    /// <summary>The hybrid ciphertext to transmit to the recipient.</summary>
    public HybridKemCiphertext Ciphertext { get; }

    /// <summary>
    /// The derived 32-byte shared secret as a raw <see cref="byte"/> array.
    /// Treat as sensitive material. For new code prefer <see cref="Secret"/>,
    /// which discourages direct misuse and integrates with KDF / AEAD APIs
    /// via implicit span conversion.
    /// </summary>
    public byte[] SharedSecret
    {
        get
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(HybridKemEncapsulationResult));
            }
            return _sharedSecret;
        }
    }

    /// <summary>
    /// The derived 32-byte shared secret as a typed <see cref="HybridSharedSecret"/>.
    /// Discourages the common misuse of treating the raw bytes as a finished
    /// symmetric key; pass it directly to <c>HKDF.Expand</c> or as
    /// <c>associatedData</c> via the built-in span conversion.
    /// </summary>
    public HybridSharedSecret Secret
    {
        get
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(HybridKemEncapsulationResult));
            }
            return new HybridSharedSecret(_sharedSecret);
        }
    }

    internal HybridKemEncapsulationResult(HybridKemCiphertext ciphertext, byte[] sharedSecret)
    {
        Ciphertext = ciphertext;
        _sharedSecret = sharedSecret;
    }

    /// <summary>Clears the cached shared secret.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        CryptographicOperations.ZeroMemory(_sharedSecret);
        _sharedSecret = Array.Empty<byte>();
        _disposed = true;
    }
}
