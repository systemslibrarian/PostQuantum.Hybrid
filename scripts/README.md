# scripts

Consumer-facing preflight tooling that helps downstream applications gather
supporting evidence for selected parts of `HARDENING-CHECKLIST.md`.

These scripts are intentionally narrower than the checklist itself. A script
can strengthen the evidence pack, but it cannot replace design review,
operational runbooks, or human judgment.

You can keep these scripts anywhere that fits your team's workflow. The
examples below assume you are invoking a local copy named `audit-pqh.ps1`;
they do not require any particular repository layout.

## `audit-pqh.ps1`

Focused preflight for .NET applications that use one or more of:

- `PostQuantum.Hybrid`
- `PostQuantum.Hybrid.Envelopes`
- `PostQuantum.Hybrid.AspNetCore`

### What it checks

- Analyzer presence for consumer projects.
- Evaluated `PQH001`–`PQH005` warnings-as-errors coverage, including values
  inherited from `Directory.Build.props`.
- `dotnet list package --vulnerable` results.
- `Export()` / `ExportPem()` call sites that need manual review for logging,
  telemetry, and exception leakage.
- Two advisory heuristics:
  - ASP.NET Core projects using `PostQuantum.Hybrid.AspNetCore` should usually
    centralize key registration with `AddPostQuantumHybrid(...)` or
    `AddRotatingHybridKemKeys(...)`.
  - Application projects that hand-roll `HybridKem.Encapsulate(...)` /
    `Decapsulate(...)` should review whether `PostQuantum.Hybrid.Envelopes`
    would be the safer surface.

### What it does NOT prove

A passing result does **not** prove full compliance with
`HARDENING-CHECKLIST.md`. The script does not prove:

- correct protocol design,
- safe logging sinks or telemetry dataflow,
- secure key storage,
- replay protection,
- readiness smoke tests,
- CI secret scanning,
- runbooks, ownership, or incident response.

### Usage

Run against a project root or workspace root:

```powershell
.\audit-pqh.ps1 -Path .
```

Run against one solution:

```powershell
.\audit-pqh.ps1 -Path .\MyApp.slnx
```

Run against one project:

```powershell
.\audit-pqh.ps1 -Path .\src\MyApp\MyApp.csproj
```

Include non-production code such as tests, samples, templates, fuzz targets,
and benchmarks in the manual review sections:

```powershell
.\audit-pqh.ps1 -Path . -IncludeNonProductionCode
```

### Default review scope

When you point the script at a directory or solution, it reviews automatic
controls across all detected consumer projects, but it limits the **manual**
review sections to production projects by default.

That means test/sample/template/fuzz/benchmark projects are skipped for:

- export call-site review,
- advisory safe-surface heuristics.

Use `-IncludeNonProductionCode` when you explicitly want those included.
If you point the script at a single `.csproj`, that project is reviewed even if
it lives under `samples/` or `tests/`.

### Exit codes

- `0`: automatic checks passed; manual review items may still exist.
- `1`: one or more automatic controls failed.
- `2`: one or more checks were inconclusive.

### Recommended workflow

1. Keep a reviewed, versioned local copy of the script in source control or
  your build environment.
2. Treat `1` as a hard failure.
3. Treat `2` as incomplete evidence, not a pass.
4. Review every manual-review finding and keep the justification with your
   hardening evidence.
5. Pair the script output with the rest of the checklist evidence pack.
