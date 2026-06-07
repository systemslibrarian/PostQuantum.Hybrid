#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Pack the library + analyzers into ./artifacts for local NuGet testing.
#>
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$out = Join-Path $repo 'artifacts'

Push-Location $repo
try {
    if (Test-Path $out) { Remove-Item -Recurse -Force $out }
    New-Item -ItemType Directory -Force -Path $out | Out-Null

    dotnet pack src/PostQuantum.Hybrid/PostQuantum.Hybrid.csproj `
        --configuration Release -o $out --nologo
    if ($LASTEXITCODE -ne 0) { throw "pack failed for PostQuantum.Hybrid" }

    dotnet pack src/PostQuantum.Hybrid.Analyzers/PostQuantum.Hybrid.Analyzers.csproj `
        --configuration Release -o $out --nologo
    if ($LASTEXITCODE -ne 0) { throw "pack failed for PostQuantum.Hybrid.Analyzers" }

    Write-Host "`nPacked to $out :" -ForegroundColor Green
    Get-ChildItem $out
} finally {
    Pop-Location
}
