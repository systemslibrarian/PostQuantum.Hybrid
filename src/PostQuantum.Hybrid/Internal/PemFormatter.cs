using System.Text;

namespace PostQuantum.Hybrid.Internal;

/// <summary>
/// Minimal RFC 7468-style PEM encoder/decoder. The library uses custom labels
/// (e.g. "PQH HYBRID KEM PUBLIC KEY") because the underlying wire format is a
/// library-specific concatenation rather than a standardized SPKI/PKCS#8 blob.
/// </summary>
internal static class PemFormatter
{
    private const int LineWidth = 64;

    public static string Encode(string label, ReadOnlySpan<byte> data)
    {
        var sb = new StringBuilder();
        sb.Append("-----BEGIN ").Append(label).Append("-----\n");
        var base64 = Convert.ToBase64String(data);
        for (int i = 0; i < base64.Length; i += LineWidth)
        {
            sb.Append(base64, i, Math.Min(LineWidth, base64.Length - i)).Append('\n');
        }
        sb.Append("-----END ").Append(label).Append("-----\n");
        return sb.ToString();
    }

    public static byte[] Decode(string pem, string expectedLabel)
    {
        ArgumentNullException.ThrowIfNull(pem);
        ArgumentNullException.ThrowIfNull(expectedLabel);

        var beginMarker = "-----BEGIN " + expectedLabel + "-----";
        var endMarker = "-----END " + expectedLabel + "-----";

        int begin = pem.IndexOf(beginMarker, StringComparison.Ordinal);
        int end = pem.IndexOf(endMarker, StringComparison.Ordinal);
        if (begin < 0 || end < 0 || end <= begin)
        {
            throw new FormatException($"PEM input does not contain a '{expectedLabel}' block.");
        }

        int bodyStart = begin + beginMarker.Length;
        var body = pem.AsSpan(bodyStart, end - bodyStart);

        var cleaned = new StringBuilder(body.Length);
        foreach (var ch in body)
        {
            if (!char.IsWhiteSpace(ch))
            {
                cleaned.Append(ch);
            }
        }

        try
        {
            return Convert.FromBase64String(cleaned.ToString());
        }
        catch (FormatException ex)
        {
            throw new FormatException($"PEM block '{expectedLabel}' contains invalid base64.", ex);
        }
    }
}
