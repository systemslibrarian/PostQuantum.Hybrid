using System.Security.Cryptography;

namespace PostQuantum.Hybrid.Internal;

/// <summary>
/// A short-lived sensitive byte buffer that zeroes itself on
/// <see cref="Dispose"/>. Use with <c>using</c> so the buffer is cleared
/// even if the enclosing scope throws.
/// </summary>
/// <remarks>
/// This is a <c>ref struct</c> so the buffer cannot escape its scope
/// (no boxing, no async-await captures, no field storage). The wrapped
/// array is heap-allocated — for stack-only material, callers should
/// keep using <c>stackalloc</c> + manual
/// <see cref="CryptographicOperations.ZeroMemory(Span{byte})"/>.
/// </remarks>
internal readonly ref struct SecureBuffer
{
    private readonly byte[] _array;

    /// <summary>Allocates a fresh zeroed byte buffer of the given length.</summary>
    public SecureBuffer(int length)
    {
        _array = new byte[length];
    }

    /// <summary>The mutable backing span.</summary>
    public Span<byte> Span => _array;

    /// <summary>A read-only view of the backing span.</summary>
    public ReadOnlySpan<byte> ReadOnlySpan => _array;

    /// <summary>The buffer's length in bytes.</summary>
    public int Length => _array.Length;

    /// <summary>Zeroes the buffer. Called by <c>using</c> scope exit.</summary>
    public void Dispose()
    {
        if (_array is not null)
        {
            CryptographicOperations.ZeroMemory(_array);
        }
    }
}
