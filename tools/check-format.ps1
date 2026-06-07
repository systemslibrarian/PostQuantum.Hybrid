#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Verify formatting via `dotnet format --verify-no-changes`. Run before PR.
#>
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Push-Location $repo
try {
    dotnet format PostQuantum.Hybrid.slnx --verify-no-changes
} finally {
    Pop-Location
}
