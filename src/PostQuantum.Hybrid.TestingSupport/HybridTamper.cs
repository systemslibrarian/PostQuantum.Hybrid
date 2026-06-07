namespace PostQuantum.Hybrid.TestingSupport;

/// <summary>
/// Deterministic tamper-injection helpers for testing fail-closed
/// behavior of hybrid wire-format artifacts.
/// </summary>
public static class HybridTamper
{
    /// <summary>Returns a copy of <paramref name="bytes"/> with one bit flipped.</summary>
    public static byte[] FlipBit(ReadOnlySpan<byte> bytes, int byteIndex, int bitIndex)
    {
        if (byteIndex < 0 || byteIndex >= bytes.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(byteIndex));
        }
        if (bitIndex < 0 || bitIndex > 7)
        {
            throw new ArgumentOutOfRangeException(nameof(bitIndex));
        }
        var copy = bytes.ToArray();
        copy[byteIndex] ^= (byte)(1 << bitIndex);
        return copy;
    }

    /// <summary>
    /// Returns a copy of <paramref name="bytes"/> with one pseudorandom
    /// bit flipped. Determined by <paramref name="seed"/> for reproducibility.
    /// </summary>
    public static byte[] FlipRandomBit(ReadOnlySpan<byte> bytes, int seed)
    {
        if (bytes.Length == 0)
        {
            throw new ArgumentException("Cannot flip a bit in an empty span.", nameof(bytes));
        }
        var rng = new Random(seed);
        var byteIndex = rng.Next(bytes.Length);
        var bitIndex = rng.Next(8);
        return FlipBit(bytes, byteIndex, bitIndex);
    }

    /// <summary>Returns a copy of <paramref name="bytes"/> truncated by <paramref name="count"/> bytes from the end.</summary>
    public static byte[] TruncateBy(ReadOnlySpan<byte> bytes, int count)
    {
        if (count < 0 || count > bytes.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(count));
        }
        return bytes[..^count].ToArray();
    }

    /// <summary>Returns a copy of <paramref name="bytes"/> extended by <paramref name="count"/> zero bytes.</summary>
    public static byte[] ExtendBy(ReadOnlySpan<byte> bytes, int count)
    {
        if (count < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(count));
        }
        var extended = new byte[bytes.Length + count];
        bytes.CopyTo(extended);
        return extended;
    }
}
