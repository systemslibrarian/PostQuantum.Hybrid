## What this PR does

<!-- A short description of the change. Link any related issue. -->

## Why

<!-- The motivation. What problem does this solve? What user value does it add? -->

## How

<!-- Implementation notes. Anything reviewers should look at first. -->

## Crypto-impact checklist

- [ ] Public API surface unchanged, OR `CHANGELOG.md` and README are updated.
- [ ] Wire format unchanged, OR a new algorithm-id byte was introduced
      (existing blobs still parse).
- [ ] Tests added for any new behavior; tampering / negative tests included
      where the change touches verification logic.
- [ ] If a new external dependency was added, an ADR was written under
      `docs/adr/` justifying it.
- [ ] `dotnet build` and `dotnet test` pass on both `net8.0` and `net10.0`.
- [ ] If sensitive material is added to any new code path, it is zeroed
      with `CryptographicOperations.ZeroMemory` and held in an
      `IDisposable` type.
