#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Compare a BenchmarkDotNet run against the pinned baseline. Exit 1 if
    any benchmark's Mean regresses by more than RegressionThreshold.
.PARAMETER ResultsGlob
    Glob (relative to the repo root) of BDN -report-full.json files.
.PARAMETER Baseline
    Path to the baseline JSON file.
#>
param(
    [Parameter(Mandatory)] [string]$ResultsGlob,
    [Parameter(Mandatory)] [string]$Baseline
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $Baseline)) {
    throw "Baseline not found: $Baseline"
}
$baselineDoc = Get-Content $Baseline | ConvertFrom-Json
$threshold = $baselineDoc.regressionThreshold

# Index baseline by method.
$baselineIndex = @{}
foreach ($entry in $baselineDoc.benchmarks) {
    $baselineIndex[$entry.method] = $entry
}

$results = @()
foreach ($file in Get-ChildItem -Path $ResultsGlob -ErrorAction SilentlyContinue) {
    $doc = Get-Content $file | ConvertFrom-Json
    foreach ($b in $doc.Benchmarks) {
        $params = if ($b.Parameters) { "[$($b.Parameters)]" } else { "" }
        $method = "$($b.Type).$($b.Method)$params"
        $results += [PSCustomObject]@{
            Method = $method
            MeanNs = [double]$b.Statistics.Mean
            AllocatedBytes = if ($b.Memory) { [long]$b.Memory.BytesAllocatedPerOperation } else { 0 }
        }
    }
}

$regressions = @()
foreach ($r in $results) {
    if (-not $baselineIndex.ContainsKey($r.Method)) {
        Write-Host "skip (not in baseline): $($r.Method)"
        continue
    }
    $base = $baselineIndex[$r.Method]
    $delta = ($r.MeanNs - $base.meanNs) / $base.meanNs
    $marker = if ($delta -gt $threshold) { 'REGRESSION' } elseif ($delta -lt -0.10) { 'IMPROVED' } else { '...' }
    Write-Host ("{0,-60} mean={1,10:N0}ns base={2,10:N0}ns delta={3,+6:P1}  {4}" -f $r.Method, $r.MeanNs, $base.meanNs, $delta, $marker)
    if ($delta -gt $threshold) {
        $regressions += $r
    }
}

if ($regressions.Count -gt 0) {
    Write-Host ""
    Write-Host "$($regressions.Count) regression(s) past +$($threshold * 100)% threshold." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "All benchmarks within $($threshold * 100)% of baseline." -ForegroundColor Green
exit 0
