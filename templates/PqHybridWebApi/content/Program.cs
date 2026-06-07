// =============================================================================
// PostQuantum.Hybrid ASP.NET Core API starter.
//
// Two endpoints out of the box:
//   GET  /pub/kem-public-key   - publish recipient KEM public key (PEM)
//   GET  /pub/sig-public-key   - publish signature verification key (PEM)
//   POST /seal                 - { "plaintext": "..." } -> envelope (b64)
//   POST /sign                 - { "data": "..." }       -> signature (b64)
//
// Configuration: bind a "Crypto" section to HybridCryptoOptions. For
// production, use KemPrivateKeyPath / SignaturePrivateKeyPath pointing
// at files in a secrets directory; rotate them via the
// AddRotatingHybridKemKeys / AddRotatingHybridSignatureKeys helpers.
// =============================================================================

using System.Text;
using PostQuantum.Hybrid;
using PostQuantum.Hybrid.AspNetCore;
using PostQuantum.Hybrid.Envelopes;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddPostQuantumHybrid(builder.Configuration.GetSection("Crypto"));

var app = builder.Build();

app.MapGet("/", () => Results.Text(
    "PostQuantum.Hybrid Web API. Endpoints: /pub/kem-public-key, /pub/sig-public-key, POST /seal, POST /sign."));

app.MapGet("/pub/kem-public-key", (IHybridKemKeyProvider keys) =>
    Results.Text(keys.PublicKey.ExportPem(), "application/x-pem-file"));

app.MapGet("/pub/sig-public-key", (IHybridSignatureKeyProvider keys) =>
    Results.Text(keys.PublicKey.ExportPem(), "application/x-pem-file"));

app.MapPost("/seal", ([FromBody] SealRequest req, IHybridKemKeyProvider keys) =>
{
    var envelope = HybridEnvelope.Seal(keys.PublicKey, Encoding.UTF8.GetBytes(req.Plaintext));
    return Results.Json(new { envelope = Convert.ToBase64String(envelope) });
});

app.MapPost("/sign", ([FromBody] SignRequest req, IHybridSignatureKeyProvider keys) =>
{
    var sig = HybridSignature.Sign(keys.PrivateKey, Encoding.UTF8.GetBytes(req.Data));
    return Results.Json(new { signature = Convert.ToBase64String(sig) });
});

app.Run();

record SealRequest(string Plaintext);
record SignRequest(string Data);
