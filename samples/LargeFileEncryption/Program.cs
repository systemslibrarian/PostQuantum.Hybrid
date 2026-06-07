// =============================================================================
// PostQuantum.Hybrid sample: chunked large-file encryption.
//
// PostQuantum.Hybrid (and Envelopes) operate on complete byte spans. For
// multi-gigabyte files you don't want to load the whole payload into
// memory. This sample shows the canonical pattern:
//
//   1) One hybrid KEM exchange against the recipient's public key.
//   2) HKDF-Expand the 32-byte shared secret with the KEM ciphertext bound
//      in 'info', producing a 32-byte AES-256-GCM master key.
//   3) Stream the file in fixed-size chunks. For each chunk:
//        - 12-byte nonce = 4 zero bytes || 8-byte big-endian chunk index
//        - 16-byte AES-GCM tag
//        - associatedData = "PQH-LFE v1 chunk" || chunk index || final-flag
//   4) Final chunk is marked with associatedData.lastByte = 0x01 so a
//      truncation attack on the file would change the AAD on the would-be
//      last chunk and fail to decrypt.
//
// Wire format (encrypted file):
//
//   [ 4B  magic = "PQHL" ]
//   [ 1B  format version = 0x01 ]
//   [ 4B  chunk-size LE ]
//   [ 1121B hybrid KEM ciphertext ]
//   [ N times: [ encrypted-chunk-bytes ] [ 16B tag ] ]
//
// Usage:
//   LargeFileEncryption gen <keys-prefix>
//   LargeFileEncryption seal <recipient.pub.pem> <input> <output> [chunkSize]
//   LargeFileEncryption open <recipient.priv.pem> <input> <output>
// =============================================================================

using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using PostQuantum.Hybrid;

const int DefaultChunkSize = 64 * 1024;
const int KemCtSize = 1121;
const int NonceSize = 12;
const int TagSize = 16;
const byte Version = 0x01;

return args switch
{
    [ "gen", var prefix ] => Generate(prefix),
    [ "seal", var pub, var input, var output ] => Seal(pub, input, output, DefaultChunkSize),
    [ "seal", var pub, var input, var output, var chunkStr ] when int.TryParse(chunkStr, out var c) =>
        Seal(pub, input, output, c),
    [ "open", var priv, var input, var output ] => Open(priv, input, output),
    _ => Usage(),
};

static int Usage()
{
    Console.Error.WriteLine(
        "usage:\n" +
        "  LargeFileEncryption gen  <prefix>\n" +
        "  LargeFileEncryption seal <recipient.pub.pem>  <input> <output> [chunkSize=65536]\n" +
        "  LargeFileEncryption open <recipient.priv.pem> <input> <output>");
    return 1;
}

static int Generate(string prefix)
{
    using var pair = HybridKem.GenerateKeyPair();
    File.WriteAllText(prefix + ".pub.pem", pair.PublicKey.ExportPem());
    File.WriteAllText(prefix + ".priv.pem", pair.PrivateKey.ExportPem());
    if (!OperatingSystem.IsWindows())
    {
        File.SetUnixFileMode(prefix + ".priv.pem", UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
    Console.WriteLine($"wrote {prefix}.pub.pem and {prefix}.priv.pem");
    return 0;
}

static int Seal(string pubKeyPath, string inputPath, string outputPath, int chunkSize)
{
    if (chunkSize <= 0)
    {
        Console.Error.WriteLine("chunkSize must be positive.");
        return 1;
    }

    // TryImportPem at the trust boundary — the file on disk could be
    // anything. A throwing Import would also work; the Try variant just
    // lets us shape the error explicitly.
    if (!HybridKemPublicKey.TryImportPem(File.ReadAllText(pubKeyPath), out var pub))
    {
        Console.Error.WriteLine($"refusing to use {pubKeyPath}: malformed hybrid KEM public PEM.");
        return 1;
    }
    using var encapsulation = HybridKem.Encapsulate(pub);
    var kemCt = encapsulation.Ciphertext.ToBytes();
    // Use the typed Secret wrapper (implicit-converts to ReadOnlySpan)
    // so the raw shared secret never escapes the call site as a byte[].
    var aesKey = DeriveKey(encapsulation.Secret, kemCt);
    try
    {
        using var aes = new AesGcm(aesKey, TagSize);

        using var input = File.OpenRead(inputPath);
        using var output = File.Create(outputPath);

        output.Write("PQHL"u8);
        output.WriteByte(Version);
        Span<byte> chunkSizeBytes = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(chunkSizeBytes, chunkSize);
        output.Write(chunkSizeBytes);
        output.Write(kemCt);

        var buffer = new byte[chunkSize];
        var ciphertext = new byte[chunkSize];
        Span<byte> tag = stackalloc byte[TagSize];
        Span<byte> nonce = stackalloc byte[NonceSize];

        long chunkIndex = 0;
        long totalIn = 0;
        while (true)
        {
            var read = ReadFull(input, buffer);
            var isFinal = read < chunkSize;
            BuildNonce(nonce, chunkIndex);
            var aad = BuildAad(chunkIndex, isFinal);
            aes.Encrypt(nonce, buffer.AsSpan(0, read), ciphertext.AsSpan(0, read), tag, associatedData: aad);
            output.Write(ciphertext, 0, read);
            output.Write(tag);
            totalIn += read;
            chunkIndex++;
            if (isFinal)
            {
                break;
            }
        }

        Console.WriteLine($"sealed {totalIn} bytes in {chunkIndex} chunks of {chunkSize} B; output {output.Length} bytes.");
        return 0;
    }
    finally
    {
        CryptographicOperations.ZeroMemory(aesKey);
    }
}

static int Open(string privKeyPath, string inputPath, string outputPath)
{
    if (!HybridKemPrivateKey.TryImportPem(File.ReadAllText(privKeyPath), out var importedPriv))
    {
        Console.Error.WriteLine($"refusing to use {privKeyPath}: malformed hybrid KEM private PEM.");
        return 1;
    }
    using var priv = importedPriv;

    using var input = File.OpenRead(inputPath);
    Span<byte> headerMagic = stackalloc byte[4];
    ReadAll(input, headerMagic);
    if (!headerMagic.SequenceEqual("PQHL"u8))
    {
        throw new CryptographicException("Not a PQHL file.");
    }
    if (input.ReadByte() != Version)
    {
        throw new CryptographicException("Unsupported PQHL version.");
    }
    Span<byte> chunkSizeBytes = stackalloc byte[4];
    ReadAll(input, chunkSizeBytes);
    var chunkSize = BinaryPrimitives.ReadInt32LittleEndian(chunkSizeBytes);
    if (chunkSize <= 0 || chunkSize > 64 * 1024 * 1024)
    {
        throw new CryptographicException("Suspicious chunkSize.");
    }

    var kemCt = new byte[KemCtSize];
    ReadAll(input, kemCt);

    var sharedSecret = HybridKem.Decapsulate(priv, kemCt);
    try
    {
        var aesKey = DeriveKey(sharedSecret, kemCt);
        try
        {
            using var aes = new AesGcm(aesKey, TagSize);

            using var output = File.Create(outputPath);

            var ciphertext = new byte[chunkSize];
            var plaintext = new byte[chunkSize];
            Span<byte> tag = stackalloc byte[TagSize];
            Span<byte> nonce = stackalloc byte[NonceSize];

            long chunkIndex = 0;
            long totalOut = 0;
            var remaining = input.Length - input.Position;
            while (remaining > 0)
            {
                var chunkPlusTag = (int)Math.Min(remaining, chunkSize + TagSize);
                var chunkLen = chunkPlusTag - TagSize;
                if (chunkLen < 0)
                {
                    throw new CryptographicException("Truncated file.");
                }
                ReadAll(input, ciphertext.AsSpan(0, chunkLen));
                ReadAll(input, tag);

                var isFinal = (remaining - chunkPlusTag) == 0;
                BuildNonce(nonce, chunkIndex);
                var aad = BuildAad(chunkIndex, isFinal);

                aes.Decrypt(nonce, ciphertext.AsSpan(0, chunkLen), tag, plaintext.AsSpan(0, chunkLen), associatedData: aad);
                output.Write(plaintext, 0, chunkLen);
                totalOut += chunkLen;
                chunkIndex++;
                remaining -= chunkPlusTag;
            }

            Console.WriteLine($"opened {totalOut} bytes from {chunkIndex} chunks.");
            return 0;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aesKey);
        }
    }
    finally
    {
        CryptographicOperations.ZeroMemory(sharedSecret);
    }
}

static byte[] DeriveKey(ReadOnlySpan<byte> sharedSecret, ReadOnlySpan<byte> kemCiphertext)
{
    var infoPrefix = Encoding.ASCII.GetBytes("PostQuantum.Hybrid LargeFileEncryption v1 AES-256-GCM");
    var info = new byte[infoPrefix.Length + kemCiphertext.Length];
    infoPrefix.CopyTo(info, 0);
    kemCiphertext.CopyTo(info.AsSpan(infoPrefix.Length));
    var key = new byte[32];
    HKDF.Expand(HashAlgorithmName.SHA256, sharedSecret, key, info);
    return key;
}

static void BuildNonce(Span<byte> dest, long chunkIndex)
{
    dest.Clear();
    BinaryPrimitives.WriteInt64BigEndian(dest[4..12], chunkIndex);
}

static byte[] BuildAad(long chunkIndex, bool isFinal)
{
    var prefix = "PQH-LFE v1 chunk"u8;
    var aad = new byte[prefix.Length + 8 + 1];
    prefix.CopyTo(aad);
    BinaryPrimitives.WriteInt64BigEndian(aad.AsSpan(prefix.Length, 8), chunkIndex);
    aad[prefix.Length + 8] = isFinal ? (byte)0x01 : (byte)0x00;
    return aad;
}

static int ReadFull(Stream stream, byte[] buffer)
{
    int total = 0;
    while (total < buffer.Length)
    {
        var n = stream.Read(buffer, total, buffer.Length - total);
        if (n == 0)
        {
            break;
        }
        total += n;
    }
    return total;
}

static void ReadAll(Stream stream, Span<byte> buffer)
{
    while (buffer.Length > 0)
    {
        var n = stream.Read(buffer);
        if (n == 0)
        {
            throw new CryptographicException("Truncated input.");
        }
        buffer = buffer[n..];
    }
}
