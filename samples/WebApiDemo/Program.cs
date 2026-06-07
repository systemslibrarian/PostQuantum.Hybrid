// =============================================================================
// PostQuantum.Hybrid sample: minimal ASP.NET Core API.
//
// Demonstrates PostQuantum.Hybrid.AspNetCore wiring:
//   - One-time startup generates hybrid KEM and signature key pairs and feeds
//     them into the DI'd providers via inline PEM (in production you'd load
//     from a secrets file or KMS instead).
//   - GET  /pub/kem-public-key   returns the recipient KEM public key (PEM)
//   - GET  /pub/sig-public-key   returns the signature public key (PEM)
//   - POST /seal                 accepts a plaintext, returns a hybrid-KEM
//                                ciphertext + AES-GCM-encrypted payload.
//   - POST /sign                 accepts data, returns a base64 hybrid signature.
//
// This is a single-process demo; in real deployments the server holds the
// recipient KEM private key, and clients hold the signature public key for
// verifying server-issued artifacts.
// =============================================================================

using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using PostQuantum.Hybrid;
using PostQuantum.Hybrid.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// One-time bootstrap key generation — in production these come from a KMS / file.
HybridKemKeyPair bootstrapKem;
HybridSignatureKeyPair bootstrapSig;
try
{
    bootstrapKem = HybridKem.GenerateKeyPair();
    bootstrapSig = HybridSignature.GenerateKeyPair();
}
catch
{
    throw;
}

builder.Services.AddPostQuantumHybrid(options =>
{
    options.KemPublicKeyPem        = bootstrapKem.PublicKey.ExportPem();
    options.KemPrivateKeyPem       = bootstrapKem.PrivateKey.ExportPem();
    options.SignaturePublicKeyPem  = bootstrapSig.PublicKey.ExportPem();
    options.SignaturePrivateKeyPem = bootstrapSig.PrivateKey.ExportPem();
});
// The DI providers now own copies of the key material; we can dispose the
// bootstrap pairs to clear our local references.
bootstrapKem.Dispose();
bootstrapSig.Dispose();

var app = builder.Build();

app.MapGet("/", () => Results.Text(
    "PostQuantum.Hybrid WebApiDemo. See /pub/kem-public-key, /pub/sig-public-key, POST /seal, POST /sign."));

app.MapGet("/pub/kem-public-key", (IHybridKemKeyProvider keys) =>
    Results.Text(keys.PublicKey.ExportPem(), "application/x-pem-file"));

app.MapGet("/pub/sig-public-key", (IHybridSignatureKeyProvider keys) =>
    Results.Text(keys.PublicKey.ExportPem(), "application/x-pem-file"));

app.MapPost("/seal", ([FromBody] SealRequest req, IHybridKemKeyProvider keys) =>
{
    using var enc = HybridKem.Encapsulate(keys.PublicKey);
    var kemCt = enc.Ciphertext.ToBytes();

    var aesKey = new byte[32];
    HKDF.Expand(
        HashAlgorithmName.SHA256,
        enc.SharedSecret,
        aesKey,
        info: Concat("PostQuantum.Hybrid WebApiDemo v1 AES-256-GCM", kemCt));

    var plaintext = Encoding.UTF8.GetBytes(req.Plaintext);
    var nonce = RandomNumberGenerator.GetBytes(12);
    var ciphertext = new byte[plaintext.Length];
    var tag = new byte[16];
    using (var aes = new AesGcm(aesKey, 16))
    {
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData: kemCt);
    }
    CryptographicOperations.ZeroMemory(aesKey);

    return Results.Json(new SealResponse(
        KemCiphertext: Convert.ToBase64String(kemCt),
        Nonce: Convert.ToBase64String(nonce),
        Ciphertext: Convert.ToBase64String(ciphertext),
        Tag: Convert.ToBase64String(tag)));
});

app.MapPost("/sign", ([FromBody] SignRequest req, IHybridSignatureKeyProvider keys) =>
{
    var data = Encoding.UTF8.GetBytes(req.Data);
    var sig = HybridSignature.Sign(keys.PrivateKey, data);
    return Results.Json(new SignResponse(Convert.ToBase64String(sig)));
});

app.Run();

static byte[] Concat(string label, ReadOnlySpan<byte> tail)
{
    var labelBytes = Encoding.ASCII.GetBytes(label);
    var buf = new byte[labelBytes.Length + tail.Length];
    labelBytes.CopyTo(buf, 0);
    tail.CopyTo(buf.AsSpan(labelBytes.Length));
    return buf;
}

record SealRequest(string Plaintext);
record SealResponse(string KemCiphertext, string Nonce, string Ciphertext, string Tag);
record SignRequest(string Data);
record SignResponse(string Signature);
