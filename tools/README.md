# tools

Repo maintenance and developer-convenience scripts. These are not part
of the published package.

| Script | Purpose |
|---|---|
| [`run-all.ps1`](run-all.ps1) | Build + test + run every sample on every TFM. The canonical "is the whole repo green?" command. |
| [`pack-local.ps1`](pack-local.ps1) | Pack the library and analyzers into `./artifacts` for local NuGet testing. |
| [`check-format.ps1`](check-format.ps1) | Verify formatting via `dotnet format --verify-no-changes`. |
