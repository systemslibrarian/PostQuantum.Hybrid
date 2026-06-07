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

    /// <summary>The derived 32-byte shared secret. Treat as sensitive material.</summary>
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
