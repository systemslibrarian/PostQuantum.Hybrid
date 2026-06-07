# Supply Chain

How PostQuantum.Hybrid is built, packaged, and what consumers can do to
verify a release.

## Dependencies

The published `PostQuantum.Hybrid` package depends on exactly one
production third-party package:

| Package | Why | Author |
|---|---|---|
| `BouncyCastle.Cryptography` (>= 2.6.2) | X25519, Ed25519 (always); ML-KEM-768 + ML-DSA-65 on net8.0 only. | Legion of the Bouncy Castle |

Everything else is `System.Security.Cryptography` (BCL).

`PostQuantum.Hybrid.AspNetCore` adds these standard
`Microsoft.Extensions.*` packages, all from Microsoft:

- `Microsoft.Extensions.DependencyInjection.Abstractions`
- `Microsoft.Extensions.Configuration.Abstractions`
- `Microsoft.Extensions.Configuration.Binder`
- `Microsoft.Extensions.Options`
- `Microsoft.Extensions.Logging.Abstractions`

No other production third-party packages.

## Build posture

- **Deterministic builds.** `<Deterministic>true</Deterministic>` is set
  in `src/PostQuantum.Hybrid/PostQuantum.Hybrid.csproj` and
  `src/PostQuantum.Hybrid.AspNetCore/PostQuantum.Hybrid.AspNetCore.csproj`.
- **`ContinuousIntegrationBuild`** is automatically set in CI
  (conditional on `$(GITHUB_ACTIONS) == 'true'`). This pins
  embedded build paths and timestamps so the same source produces the
  same nupkg bytes.
- **SourceLink** via `Microsoft.SourceLink.GitHub` embeds the GitHub
  commit URL into the symbols so debuggers can step into the library's
  source.
- **`EmbedUntrackedSources=true`** ensures generated source (e.g. from
  source generators) is also included.
- **Symbol packages (`.snupkg`)** are published alongside the main
  packages.

## What a consumer can verify

After installing a release:

```bash
# Find the package on disk
PKG=~/.nuget/packages/postquantum.hybrid/1.0.0

# Verify the file came from the documented repo (SourceLink)
strings $PKG/lib/net10.0/PostQuantum.Hybrid.dll | grep -i sourcelink
strings $PKG/lib/net10.0/PostQuantum.Hybrid.dll | grep "github.com/systemslibrarian"

# Verify the PDB embeds the SourceLink mapping
dotnet sourcelink test $PKG/lib/net10.0/PostQuantum.Hybrid.pdb \
    --url-prefix https://raw.githubusercontent.com/systemslibrarian/PostQuantum.Hybrid

# Compare your local build of the same tag against the released nupkg
git checkout v1.0.0
pwsh tools/pack-local.ps1
sha256sum artifacts/PostQuantum.Hybrid.1.0.0.nupkg \
          $PKG/postquantum.hybrid.1.0.0.nupkg
```

If `ContinuousIntegrationBuild` is set on the local build and the build
machine has the same SDK, the hashes should match modulo the embedded
build timestamp (which is normalized to a constant under
`ContinuousIntegrationBuild`).

## Release transparency artifacts

| Artifact | State | Where |
|---|---|---|
| GitHub release notes | ✅ shipped per release | Releases page |
| SourceLink debug info | ✅ enabled | `.pdb` inside `.snupkg` |
| Deterministic build | ✅ enabled in CI | nupkg metadata |
| CycloneDX SBOM | ⏳ planned (KNOWN-GAPS) | — |
| Sigstore provenance | ⏳ under evaluation | — |
| Authenticode signing | ⏳ planned (SignPath) | — |
| GPG signature on `.nupkg` | ❌ NuGet doesn't support | — |

## Build reproducibility

To reproduce a release locally:

```bash
git checkout v1.0.0
# Match the .NET SDK version pinned in global.json
dotnet --version  # should match
GITHUB_ACTIONS=true pwsh tools/pack-local.ps1
```

The output in `artifacts/` should be byte-for-byte identical to the
published `.nupkg` (excluding `ContinuousIntegrationBuild`-normalized
timestamps).

## Reviewing a security update

When a CVE drops in a transitive dependency:

1. Watch `.github/workflows/ci.yml`'s `vulnerable-packages` job — it
   runs `dotnet list package --vulnerable --include-transitive` on every
   commit.
2. Dependabot opens a PR (configured in `.github/dependabot.yml`).
3. The PR triggers full CI; if green and the bump is patch-level, we
   merge and cut a patch release.

## Reporting a supply-chain concern

If you observe a discrepancy between source and published artifact, or
notice a transitive dependency you can't account for, please report it
privately per [SECURITY.md](../SECURITY.md).
