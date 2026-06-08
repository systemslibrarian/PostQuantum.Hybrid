// =============================================================================
// PostQuantum.Hybrid sample: minimal ASP.NET Core API.
//
// Wires PostQuantum.Hybrid.AspNetCore into a Minimal API host:
//   - One-time startup generates hybrid KEM and signature key pairs and
//     feeds them into the DI'd providers via inline PEM (in production
//     these come from a secrets file / KMS / IDataProtector).
//   - GET  /pub/kem-public-key   returns the recipient KEM public key (PEM)
//   - GET  /pub/sig-public-key   returns the signature public key (PEM)
//   - POST /seal                 server-side encryption against the
//                                hosted KEM key. Returns base64(KEM ct,
//                                nonce, AES-GCM ct, tag).
//   - POST /sign                 server-side hybrid signature.
//
// Swagger UI is mounted at the site root so the deployed URL renders a
// clickable interactive page (Azure Container Apps users land on the UI,
// no curl required).
//
// Production guidance (this sample is single-process for clarity):
//   • The server holds the KEM private key. Clients hold the signature
//     PUBLIC key only — they verify server-issued artifacts with it.
//   • Use IRotatingHybridKemKeyProvider (in PostQuantum.Hybrid.AspNetCore)
//     to swap keys on disk without restarting. This sample uses the
//     simpler in-memory provider.
//   • For envelope encryption from clients, prefer IDataProtector via
//     HybridEnvelopeDataProtector — it handles per-purpose AAD binding.
// =============================================================================

using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.OpenApi.Models;
using PostQuantum.Hybrid;
using PostQuantum.Hybrid.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// One-time bootstrap key generation. Compute PEM payloads up front so
// the bootstrap pairs can be disposed immediately; the options lambda
// below runs lazily on first DI resolve, so it must NOT capture the
// disposable key-pair instances directly (that would surface as
// ObjectDisposedException on the first request — and did in v1.0-rc).
string kemPubPem, kemPrivPem, sigPubPem, sigPrivPem;
using (var bootstrapKem = HybridKem.GenerateKeyPair())
using (var bootstrapSig = HybridSignature.GenerateKeyPair())
{
    kemPubPem  = bootstrapKem.PublicKey.ExportPem();
    kemPrivPem = bootstrapKem.PrivateKey.ExportPem();
    sigPubPem  = bootstrapSig.PublicKey.ExportPem();
    sigPrivPem = bootstrapSig.PrivateKey.ExportPem();
}

builder.Services.AddPostQuantumHybrid(options =>
{
    options.KemPublicKeyPem        = kemPubPem;
    options.KemPrivateKeyPem       = kemPrivPem;
    options.SignaturePublicKeyPem  = sigPubPem;
    options.SignaturePrivateKeyPem = sigPrivPem;
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c => c.SwaggerDoc("v1", new OpenApiInfo
{
    Title = "PostQuantum.Hybrid WebApiDemo",
    Version = "v1",
    Description =
        "Interactive demo for the PostQuantum.Hybrid .NET library. " +
        "GET the server's hybrid public keys, POST plaintext to /seal " +
        "(X25519 + ML-KEM-768 + AES-256-GCM with KEM ct bound into AAD), " +
        "POST data to /sign (Ed25519 + ML-DSA-65). " +
        "See https://www.nuget.org/packages/PostQuantum.Hybrid.",
}));

var app = builder.Build();

// Mount Swagger UI at the site root so the deployed URL renders a
// clickable page. RoutePrefix = "" replaces the default /swagger landing.
app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "PostQuantum.Hybrid WebApiDemo v1");
    c.RoutePrefix = string.Empty;
    c.DocumentTitle = "PostQuantum.Hybrid WebApiDemo";
});

app.MapGet("/pub/kem-public-key", (IHybridKemKeyProvider keys) =>
    Results.Text(keys.PublicKey.ExportPem(), "application/x-pem-file"))
   .WithName("GetKemPublicKey")
   .WithSummary("Hybrid KEM recipient public key (PEM).")
   .WithDescription(
       "Returns the X25519 + ML-KEM-768 hybrid public key the server uses " +
       "for /seal. Clients can encapsulate against this key directly with " +
       "HybridKem.Encapsulate.")
   .WithTags("Keys");

app.MapGet("/pub/sig-public-key", (IHybridSignatureKeyProvider keys) =>
    Results.Text(keys.PublicKey.ExportPem(), "application/x-pem-file"))
   .WithName("GetSignaturePublicKey")
   .WithSummary("Hybrid signature public key (PEM).")
   .WithDescription(
       "Returns the Ed25519 + ML-DSA-65 hybrid public key. Clients verify " +
       "/sign output against this key with HybridSignature.Verify.")
   .WithTags("Keys");

app.MapPost("/seal", ([FromBody] SealRequest req, IHybridKemKeyProvider keys) =>
{
    if (req is null || req.Plaintext is null)
    {
        return Results.BadRequest("missing 'plaintext'.");
    }

    // Encapsulate against our hosted KEM public key. `using` zeroes the
    // shared-secret buffer on scope exit even if encryption throws.
    using var enc = HybridKem.Encapsulate(keys.PublicKey);
    var kemCt = enc.Ciphertext.ToBytes();

    // Derive an AES key from the hybrid shared secret via HKDF. We use
    // enc.Secret (typed wrapper, implicit-converts to ReadOnlySpan)
    // instead of enc.SharedSecret so the secret never appears as a
    // raw byte[] in this method — PQH002 would flag that pattern.
    var aesKey = new byte[32];
    HKDF.Expand(
        HashAlgorithmName.SHA256,
        enc.Secret,
        aesKey,
        info: Concat("PostQuantum.Hybrid WebApiDemo v1 AES-256-GCM", kemCt));

    try
    {
        var plaintext = Encoding.UTF8.GetBytes(req.Plaintext);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        using (var aes = new AesGcm(aesKey, 16))
        {
            // KEM ct binds into AAD — PQH005 enforces this at build time.
            aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData: kemCt);
        }

        return Results.Json(new SealResponse(
            KemCiphertext: Convert.ToBase64String(kemCt),
            Nonce: Convert.ToBase64String(nonce),
            Ciphertext: Convert.ToBase64String(ciphertext),
            Tag: Convert.ToBase64String(tag)));
    }
    finally
    {
        CryptographicOperations.ZeroMemory(aesKey);
    }
})
.WithName("Seal")
.WithSummary("Encrypt a plaintext under the server's hybrid KEM key.")
.WithDescription(
    "Hybrid KEM encapsulation (X25519 + ML-KEM-768) + HKDF-SHA256 + " +
    "AES-256-GCM, with the KEM ciphertext bound into the AEAD " +
    "associated data so a swapped KEM ct causes decryption to fail.")
.WithTags("Crypto");

app.MapPost("/sign", ([FromBody] SignRequest req, IHybridSignatureKeyProvider keys) =>
{
    if (req is null || req.Data is null)
    {
        return Results.BadRequest("missing 'data'.");
    }

    var data = Encoding.UTF8.GetBytes(req.Data);
    var sig = HybridSignature.Sign(keys.PrivateKey, data);
    return Results.Json(new SignResponse(Convert.ToBase64String(sig)));
})
.WithName("Sign")
.WithSummary("Hybrid-sign a payload (Ed25519 + ML-DSA-65).")
.WithDescription(
    "Produces a hybrid signature over the supplied data. Verifying " +
    "clients use HybridSignature.Verify with the public key from " +
    "/pub/sig-public-key.")
.WithTags("Crypto");

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
