#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Build + test + run every sample on every target framework.
.DESCRIPTION
    The canonical "is the whole repo green?" command. Run before pushing.
#>
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

Push-Location $repo
try {
    Write-Host "=== build (Release) ==="
    dotnet build PostQuantum.Hybrid.slnx --configuration Release --nologo
    if ($LASTEXITCODE -ne 0) { throw "build failed" }

    Write-Host "=== test ==="
    dotnet test PostQuantum.Hybrid.slnx --configuration Release --no-build --nologo
    if ($LASTEXITCODE -ne 0) { throw "test failed" }

    $samples = @('BasicDemo','KemEncryption','SignedDocument','KeyPersistence','SecureMessenger')
    foreach ($tfm in 'net8.0','net10.0') {
        foreach ($sample in $samples) {
            Write-Host "=== sample $sample on $tfm ==="
            dotnet run --project "samples/$sample" --framework $tfm --configuration Release --no-build
            if ($LASTEXITCODE -ne 0) { throw "sample $sample failed on $tfm" }
        }
    }

    Write-Host "`nAll checks green." -ForegroundColor Green
} finally {
    Pop-Location
}
