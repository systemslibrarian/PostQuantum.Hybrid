# Release Process

The PostQuantum.Hybrid release process is fully automated via the
`v*.*.*` tag trigger.

## Checklist

Before tagging:

- [ ] CI is green on `main` for the commit you intend to tag.
- [ ] `CHANGELOG.md` has the entries for this version moved out of
      "Unreleased" into a dated heading.
- [ ] `Version` in `src/PostQuantum.Hybrid/PostQuantum.Hybrid.csproj`
      matches the tag.
- [ ] `Version` in `src/PostQuantum.Hybrid.Analyzers/PostQuantum.Hybrid.Analyzers.csproj`
      matches the tag.
- [ ] `Version` in `templates/PqHybridApp/PostQuantum.Hybrid.Templates.csproj`
      matches the tag.
- [ ] Analyzer release-tracking files updated: rule entries moved from
      `AnalyzerReleases.Unshipped.md` into `AnalyzerReleases.Shipped.md`.
- [ ] If the wire format changed: a new algorithm-id byte was used (we
      NEVER break wire compatibility within a major version).
- [ ] If a new public type was added or an existing one was changed:
      `docs/SPEC.md` reflects it.

## Tagging

```bash
git tag v1.0.0
git push origin v1.0.0
```

The `.github/workflows/release.yml` workflow then:

1. Builds and tests both target frameworks.
2. Packs all six packages (`PostQuantum.Hybrid`, `Envelopes`, `AspNetCore`,
   `Analyzers`, `TestingSupport`, `Templates`) with
   `ContinuousIntegrationBuild=true` for deterministic builds and
   SourceLink.
3. Attaches the `.nupkg` and `.snupkg` files to a GitHub release.
4. Pushes to NuGet.org via **Trusted Publishing** — short-lived API
   keys minted from a GitHub OIDC token. No long-lived
   `NUGET_API_KEY` secret. Setup runbook:
   [`TRUSTED-PUBLISHING.md`](TRUSTED-PUBLISHING.md).

## SemVer policy

- **Major** — wire format breakage (very rare; we use new algorithm-ids
  for additions instead). Public-API removal or rename.
- **Minor** — public-API additions (new types, new methods, new
  algorithm-id combinations).
- **Patch** — bug fixes that don't change behavior, dependency bumps,
  doc-only changes, security fixes.

A new algorithm-id combination is a **minor** bump, never a major one,
because old blobs continue to parse and verify.

## Yanking

If a released version has a critical bug:

1. **Do not delete the tag.** Yank the NuGet package via the NuGet
   web UI (Listed → Unlist).
2. Add a `## [x.y.z] — Yanked YYYY-MM-DD` entry to `CHANGELOG.md`
   explaining the issue.
3. Cut a patch release with the fix.

For security issues specifically, follow `SECURITY.md` first
(coordinated disclosure), then yank and release a patch as the public
mitigation.

## Post-release

- [ ] Update `CHANGELOG.md` to add a new `## [Unreleased]` heading.
- [ ] Update `templates/PqHybridApp/.template.config/template.json`
      `PackageVersion` default to the new version.
- [ ] Announce in `docs/` and on GitHub Discussions.
