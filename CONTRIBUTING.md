# Contributing to PostQuantum.Hybrid

Thanks for your interest in contributing! This project aims to be the
go-to, production-quality hybrid post-quantum cryptography library for .NET.

## Ground rules

- **Security first.** Crypto code is held to a higher bar. Every change to
  algorithm logic must come with tests and a clear rationale.
- **No new dependencies** beyond BouncyCastle without discussion.
- **Wire-format stability.** The serialized formats for keys, ciphertexts,
  and signatures are part of the public contract. Any change requires a
  new algorithm identifier (so v1 blobs continue to parse).
- **Both backends must agree.** Tests run on `net8.0` (BouncyCastle backend)
  and `net10.0` (native backend). A change is not done until both pass.

## Development

```bash
# Build
dotnet build PostQuantum.Hybrid.slnx

# Run all tests on both target frameworks
dotnet test PostQuantum.Hybrid.slnx

# Run a sample
dotnet run --project samples/PostQuantum.Hybrid.Sample
```

## Pull requests

1. Open an issue first for non-trivial changes so we can align on direction.
2. Keep PRs focused — one concern per PR.
3. Add tests for every behavior change.
4. Update `CHANGELOG.md` under the **Unreleased** heading.
5. Update XML documentation for any public-API change.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Please **do not** open a public issue for
suspected vulnerabilities.
