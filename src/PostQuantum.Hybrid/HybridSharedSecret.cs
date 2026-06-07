using System.Security.Cryptography;

namespace PostQuantum.Hybrid;

/// <summary>
/// A typed wrapper around the 32-byte secret produced by a hybrid KEM
/// exchange. Discourages the common misuse of treating the raw bytes as
/// a finished symmetric key, and centralises explicit zeroing.
/// </summary>
/// <remarks>
/// <para>The secret should be fed through a key-derivation function
/// (e.g. <c>HKDF.Expand</c> or <c>HKDF.DeriveKey</c>) with a
/// purpose-specific <c>info</c> parameter before being used as the key
/// for an AEAD or MAC. The Roslyn rule <c>PQH002</c> catches the most
/// common misuse pattern at build time.</para>
/// <para>This struct is intentionally implicit-convertible to
/// <see cref="ReadOnlySpan{T}"/> of <see cref="byte"/>, so it can be
/// passed directly to APIs like <c>HKDF.Expand</c> or
/// <c>AesGcm.Encrypt</c>'s <c>associatedData</c> parameter without
/// boilerplate. It does <em>not</em> implicitly convert to
/// <see cref="byte"/><c>[]</c> because that would defeat the wrapping.</para>
/// </remarks>
public readonly struct HybridSharedSecret
{
    private readonly byte[]? _bytes;

    internal HybridSharedSecret(byte[] bytes)
    {
        _bytes = bytes;
    }

    /// <summary>Length of the secret in bytes (always 32 for v1).</summary>
    public int Length => _bytes?.Length ?? 0;

    /// <summary><see langword="true"/> if this is the default / cleared instance.</summary>
    public bool IsEmpty => _bytes is null || _bytes.Length == 0;

    /// <summary>Returns a read-only view of the secret bytes.</summary>
    public ReadOnlySpan<byte> AsSpan() => _bytes;

    /// <summary>Copies the secret into <paramref name="destination"/>.</summary>
    public void CopyTo(Span<byte> destination)
    {
        if (_bytes is null)
        {
            return;
        }
        _bytes.CopyTo(destination);
    }

    /// <summary>
    /// Returns a fresh <see cref="byte"/><c>[]</c> copy of the secret.
    /// The returned array contains sensitive material — clear it with
    /// <see cref="CryptographicOperations.ZeroMemory(Span{byte})"/> after
    /// use, or prefer <see cref="AsSpan"/> / <see cref="CopyTo"/>.
    /// </summary>
    public byte[] ToArray()
    {
        if (_bytes is null)
        {
            return Array.Empty<byte>();
        }
        var copy = new byte[_bytes.Length];
        _bytes.CopyTo(copy.AsSpan());
        return copy;
    }

    /// <summary>
    /// Zeroes the underlying buffer. After this call the secret is
    /// equivalent to the default instance; subsequent reads via
    /// <see cref="AsSpan"/> return an empty span.
    /// </summary>
    public void Clear()
    {
        if (_bytes is not null)
        {
            CryptographicOperations.ZeroMemory(_bytes);
        }
    }

    /// <summary>
    /// Implicit conversion to <see cref="ReadOnlySpan{T}"/> so the secret
    /// flows naturally into KDF / AEAD APIs that take span inputs.
    /// </summary>
    public static implicit operator ReadOnlySpan<byte>(HybridSharedSecret secret)
        => secret.AsSpan();
}
