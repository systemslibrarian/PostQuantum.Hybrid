# Downloads the Wycheproof (C2SP) negative test vectors for the classical
# primitives this library wraps (X25519, Ed25519) plus the ML-DSA-65 verify
# vectors, and writes them as vendored test fixtures under
# tests/PostQuantum.Hybrid.Tests/fixtures/wycheproof/.
#
# Wycheproof is Apache-2.0; a NOTICE.md recording the source commit and the
# license is written next to the fixtures.
#
# Usage (from the repo root):
#   powershell -ExecutionPolicy Bypass -File tools/fetch-wycheproof.ps1

$ErrorActionPreference = "Stop"

$repoApi = "https://api.github.com/repos/C2SP/wycheproof"
$fixtureDir = Join-Path $PSScriptRoot "..\tests\PostQuantum.Hybrid.Tests\fixtures\wycheproof"
New-Item -ItemType Directory -Force $fixtureDir | Out-Null

# Pin the exact upstream commit so the NOTICE is reproducible.
$headers = @{ "User-Agent" = "PostQuantum.Hybrid-fixture-fetch" }
$commit = (Invoke-RestMethod -Headers $headers "$repoApi/commits/main").sha
Write-Host "C2SP/wycheproof main commit: $commit"

$files = @(
    "x25519_test.json",
    "ed25519_test.json"
)

# The ML-DSA verify file name has varied across upstream revisions, so
# discover it from the directory listing instead of hard-coding it. The
# matching test (WycheproofTests) locates the fixture by the same pattern.
$listing = Invoke-RestMethod -Headers $headers "$repoApi/contents/testvectors_v1?ref=$commit"
$mldsa = @($listing | Where-Object { $_.name -match '^mldsa_65.*verify.*\.json$' } | ForEach-Object { $_.name })
if ($mldsa.Count -eq 0) {
    $all = ($listing | Where-Object { $_.name -match 'mldsa' } | ForEach-Object { $_.name }) -join ", "
    throw "No ML-DSA-65 verify file found in testvectors_v1. ML-DSA files present: $all"
}
Write-Host "ML-DSA-65 verify files discovered: $($mldsa -join ', ')"
$files += $mldsa

foreach ($f in $files) {
    $url = "https://raw.githubusercontent.com/C2SP/wycheproof/$commit/testvectors_v1/$f"
    Write-Host "Fetching $url"
    $outPath = Join-Path $fixtureDir $f
    Invoke-WebRequest -Headers $headers -Uri $url -OutFile $outPath
    $json = Get-Content $outPath -Raw | ConvertFrom-Json
    if (-not $json.testGroups -or $json.numberOfTests -lt 1) {
        throw "$f has no testGroups/numberOfTests - schema change upstream?"
    }
    $sizeKb = [math]::Round((Get-Item $outPath).Length / 1KB)
    Write-Host "  wrote $f ($sizeKb KB, $($json.numberOfTests) tests)"
}

$notice = @"
# NOTICE - Wycheproof test vectors

The JSON files in this directory are unmodified copies of test vectors
from Project Wycheproof (now maintained under C2SP).

- Source: https://github.com/C2SP/wycheproof (testvectors_v1)
- Commit: $commit
- Fetched: $(Get-Date -Format yyyy-MM-dd) by tools/fetch-wycheproof.ps1
- License: Apache License 2.0 (https://github.com/C2SP/wycheproof/blob/main/LICENSE)

Copyright the Wycheproof / C2SP contributors. Redistributed here
unmodified under the terms of the Apache License 2.0.
"@
$notice | Out-File -Encoding utf8 (Join-Path $fixtureDir "NOTICE.md")
Write-Host "wrote NOTICE.md"
