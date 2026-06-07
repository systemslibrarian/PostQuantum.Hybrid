# PostQuantum.Hybrid templates

`dotnet new` templates that scaffold a project pre-wired for
PostQuantum.Hybrid.

## Install

```bash
dotnet new install PostQuantum.Hybrid.Templates
```

## Use

```bash
mkdir my-pq-app && cd my-pq-app
dotnet new pqhybrid-app
dotnet run
```

### Options

```
--framework <value>  Target framework (net8.0 | net10.0; default net10.0)
--PackageVersion <v> Version of PostQuantum.Hybrid to depend on (default 1.0.0)
```

## Templates included

| Short name | Type | What you get |
|---|---|---|
| `pqhybrid-app` | Console | A minimal console app demonstrating hybrid KEM and signatures, with `PostQuantum.Hybrid` + `PostQuantum.Hybrid.Analyzers` already wired up. |

## Building locally

```bash
dotnet pack templates/PqHybridApp -o ./artifacts
dotnet new install ./artifacts/PostQuantum.Hybrid.Templates.1.0.0.nupkg
```
