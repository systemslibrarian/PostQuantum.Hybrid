# PostQuantum.Hybrid — Samples

Seven self-contained demos. Read them in roughly this order — they go
from "just round-trip the primitives" up to "full ASP.NET Core service."

| # | Sample | What it shows | When to read it |
|---|---|---|---|
| 1 | [`BasicDemo`](BasicDemo) | KEM round trip and signature good/tampered, in 50 lines. | First time you touch the library. |
| 2 | [`KemEncryption`](KemEncryption) | KEM → HKDF → AES-GCM — the canonical way to actually encrypt a message with a KEM. Binds the KEM ciphertext into AEAD `associatedData`. | When you want to encrypt data with a hybrid KEM. |
| 3 | [`SignedDocument`](SignedDocument) | Detached document signature; publisher signs, verifier validates with only the public key. Demonstrates tamper rejection on the document body. | When you need release-artifact / file-publication signing. |
| 4 | [`KeyPersistence`](KeyPersistence) | Generate-once / use-many: write PEM keys to disk with tightened permissions on Unix, reload them in a fresh "session," round-trip both KEM and signature. | When you need keys to survive process restarts. |
| 5 | [`SecureMessenger`](SecureMessenger) | End-to-end Alice → Bob: hybrid signature **plus** hybrid KEM **plus** AEAD with full transcript binding. The "everything together" sample. | When you need authenticated + encrypted messaging. |
| 6 | [`LargeFileEncryption`](LargeFileEncryption) | Chunked AES-GCM over a streamed file, one hybrid KEM exchange up front. Each chunk gets a unique nonce + AAD including the chunk index and final-chunk flag (defeats truncation attacks). | When the payload doesn't fit in memory. |
| 7 | [`WebApiDemo`](WebApiDemo) | ASP.NET Core Minimal API wired through `PostQuantum.Hybrid.AspNetCore`'s DI extensions and rotating key providers. GET the public keys, POST a plaintext to `/seal`, POST data to `/sign`. | When you're integrating into an ASP.NET service. |

## How to run a sample

All samples target both `net8.0` and `net10.0`. Pick a TFM:

```bash
dotnet run --project samples/BasicDemo --framework net10.0
```

To exercise every sample on both TFMs in one go — useful as a smoke test
before tagging a release — run the verification script from the repo
root:

```pwsh
pwsh tools/run-all-samples.ps1
```

It boots `WebApiDemo` in the background, hits its endpoints, and tears
it down; for `LargeFileEncryption` it drives `gen → seal → open` against
a 200 KB random file and SHA-256-diffs the recovered bytes.

## What the samples are deliberately NOT

- **Production-ready templates.** They illustrate one concept clearly.
  Real systems need key storage (KMS / HSM / `IDataProtector`), rotation,
  auditing, rate-limiting, etc. `WebApiDemo` shows the wiring for some of
  that; the others don't.
- **Coverage of every API.** They cover the canonical paths. For the
  full surface see [`docs/SPEC.md`](../docs/SPEC.md) and the test suite.
- **Performance benchmarks.** See
  [`benchmarks/PostQuantum.Hybrid.Benchmarks`](../benchmarks/PostQuantum.Hybrid.Benchmarks)
  for that.

## Templates (alternative to copying these samples)

If you want a fresh project rather than a sample to read:

```bash
dotnet new install PostQuantum.Hybrid.Templates
dotnet new pqhybrid-app      -n MyApp        # console KEM + signature
dotnet new pqhybrid-webapi   -n MyApi        # ASP.NET Core Minimal API
dotnet new pqhybrid-envelope -n MyEncryptor  # file-encryption CLI
```

The templates start from the same patterns the samples demonstrate.
