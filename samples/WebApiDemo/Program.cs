// =============================================================================
// PostQuantum.Hybrid sample: WebApiDemo (gold-standard interactive playground).
//
// This sample is the canonical reference implementation for the library. It
// runs Blazor Server at the site root so the deployed URL renders a polished
// interactive page — and keeps the same JSON endpoints behind the scenes so
// curl users (and Swagger at /swagger) still work.
//
// Surface:
//   GET  /                       Blazor Server playground (Hero, Why Hybrid?,
//                                live demo, key rotation, security hygiene,
//                                copy-pasta code, "use this in your project").
//   GET  /swagger                Swashbuckle UI (REST API discovery).
//   GET  /pub/kem-public-key     hybrid KEM recipient public key (PEM).
//   GET  /pub/sig-public-key     hybrid signature public key (PEM).
//   POST /seal                   server-side anonymous envelope. Uses the
//                                RECOMMENDED HybridEnvelope.Seal one-liner —
//                                no hand-rolled HKDF / AesGcm. Returns
//                                base64(envelope).
//   POST /sign                   server-side hybrid signature (detached).
//   GET  /api/backend            backend transparency: which ML-KEM / ML-DSA
//                                backend is live (native .NET 10 BCL vs
//                                BouncyCastle fallback per ADR 0012).
//
// Production guidance (this sample is single-process for clarity):
//   • The server holds the KEM private key. Clients hold the signature
//     PUBLIC key only — they verify server-issued artifacts with it.
//   • Use IRotatingHybridKemKeyProvider (in PostQuantum.Hybrid.AspNetCore)
//     to swap keys on disk without restarting. The KeyRotationDemo sample
//     and the playground's Rotation section both show that flow.
//   • For envelope encryption from clients, prefer IDataProtector via
//     HybridEnvelopeDataProtector — it handles per-purpose AAD binding.
// =============================================================================

using Microsoft.AspNetCore.Mvc;
using Microsoft.OpenApi.Models;
using PostQuantum.Hybrid;
using PostQuantum.Hybrid.AspNetCore;
using PostQuantum.Hybrid.Envelopes;
using PostQuantum.Hybrid.Samples.WebApiDemo.Components;
using PostQuantum.Hybrid.Samples.WebApiDemo.Services;

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

// Backend transparency: capture which ML-KEM / ML-DSA backend resolved at
// startup. The badge in the playground header reads this so visitors see
// whether the live container is exercising the native .NET 10 BCL or the
// BouncyCastle fallback. See ADR 0012.
builder.Services.AddSingleton<BackendInfoService>();

// Blazor Server. The playground is a single Razor component with anchor-link
// navigation, so we keep the component tree small and the interactive render
// mode server-side (the crypto runs on the server anyway).
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// Swagger generation for the JSON endpoints. The UI is mounted at /swagger
// rather than the site root — the root belongs to the Blazor playground now.
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c => c.SwaggerDoc("v1", new OpenApiInfo
{
    Title = "PostQuantum.Hybrid WebApiDemo",
    Version = "v1",
    Description =
        "REST surface of the PostQuantum.Hybrid interactive demo. The same " +
        "server hosts a Blazor Server playground at the site root; these JSON " +
        "endpoints are the curl-friendly equivalents. " +
        "See https://www.nuget.org/packages/PostQuantum.Hybrid.",
}));

var app = builder.Build();

app.UseStaticFiles();
app.UseAntiforgery();   // Required by Blazor Server's interactive components.

app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "PostQuantum.Hybrid WebApiDemo v1");
    c.RoutePrefix = "swagger";
    c.DocumentTitle = "PostQuantum.Hybrid WebApiDemo — REST";
});

app.MapRazorComponents<App>()
   .AddInteractiveServerRenderMode();

app.MapGet("/pub/kem-public-key", (IHybridKemKeyProvider keys) =>
    Results.Text(keys.PublicKey.ExportPem(), "application/x-pem-file"))
   .WithName("GetKemPublicKey")
   .WithSummary("Hybrid KEM recipient public key (PEM).")
   .WithDescription(
       "Returns the X25519 + ML-KEM-768 hybrid public key the server uses " +
       "for /seal. Clients can encapsulate against this key directly with " +
       "HybridKem.Encapsulate, or — recommended — call HybridEnvelope.Seal " +
       "from PostQuantum.Hybrid.Envelopes.")
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

    // RECOMMENDED PATH: HybridEnvelope.Seal does the entire pipeline in
    // one call — KEM encapsulation, HKDF-SHA256 key derivation, AES-256-GCM
    // with the KEM ciphertext bound into associatedData, nonce generation,
    // and zeroization of the intermediate shared-secret buffer. This is
    // what production code should look like.
    var plaintext = System.Text.Encoding.UTF8.GetBytes(req.Plaintext);
    var envelope = HybridEnvelope.Seal(keys.PublicKey, plaintext);
    return Results.Json(new SealResponse(
        Envelope: Convert.ToBase64String(envelope),
        EnvelopeBytes: envelope.Length,
        OverheadBytes: HybridEnvelope.OverheadBytes));
})
.WithName("Seal")
.WithSummary("Encrypt a plaintext under the server's hybrid KEM key (HybridEnvelope.Seal).")
.WithDescription(
    "Uses the recommended high-level API: HybridEnvelope.Seal. One call " +
    "performs KEM encapsulation (X25519 + ML-KEM-768), HKDF-SHA256 key " +
    "derivation, AES-256-GCM with the KEM ciphertext bound into associated " +
    "data, and shared-secret zeroization. The response includes the byte " +
    "envelope and the fixed overhead constant for transparency.")
.WithTags("Crypto");

app.MapPost("/sign", ([FromBody] SignRequest req, IHybridSignatureKeyProvider keys) =>
{
    if (req is null || req.Data is null)
    {
        return Results.BadRequest("missing 'data'.");
    }

    var data = System.Text.Encoding.UTF8.GetBytes(req.Data);
    var sig = HybridSignature.Sign(keys.PrivateKey, data);
    return Results.Json(new SignResponse(Convert.ToBase64String(sig)));
})
.WithName("Sign")
.WithSummary("Hybrid-sign a payload (Ed25519 + ML-DSA-65).")
.WithDescription(
    "Produces a detached hybrid signature over the supplied data. " +
    "Verifying clients call HybridSignature.Verify with the public key " +
    "from /pub/sig-public-key.")
.WithTags("Crypto");

app.MapGet("/api/backend", (BackendInfoService backend) =>
    Results.Json(new
    {
        kemBackend       = backend.KemBackendName,
        signatureBackend = backend.SignatureBackendName,
        runtimeFramework = backend.RuntimeFramework,
        osDescription    = backend.OSDescription,
        nativePqAvailable = backend.NativePqAvailable,
    }))
   .WithName("GetBackend")
   .WithSummary("Backend transparency.")
   .WithDescription(
       "Reports which ML-KEM / ML-DSA backend resolved at startup (native " +
       ".NET 10 BCL vs BouncyCastle fallback per ADR 0012). The Blazor " +
       "playground reads this for the header badge.")
   .WithTags("Diagnostics");

app.Run();

record SealRequest(string Plaintext);
record SealResponse(string Envelope, int EnvelopeBytes, int OverheadBytes);
record SignRequest(string Data);
record SignResponse(string Signature);
