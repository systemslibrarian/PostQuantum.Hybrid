# Downloads the NIST ACVP gen-val test vectors for the final FIPS 203 / 204
# standards, filters them to the parameter sets this library ships
# (ML-KEM-768, ML-DSA-65), and writes them as vendored test fixtures under
# tests/PostQuantum.Hybrid.Tests/fixtures/nist-acvp/.
#
# The vectors are NIST-authored works, not subject to copyright in the
# United States (17 U.S.C. 105); a NOTICE.md recording the source commit is
# written next to the fixtures.
#
# Usage (from the repo root):
#   powershell -ExecutionPolicy Bypass -File tools/fetch-nist-acvp.ps1

$ErrorActionPreference = "Stop"

$repoApi = "https://api.github.com/repos/usnistgov/ACVP-Server"
$fixtureDir = Join-Path $PSScriptRoot "..\tests\PostQuantum.Hybrid.Tests\fixtures\nist-acvp"
New-Item -ItemType Directory -Force $fixtureDir | Out-Null

# Pin the exact upstream commit so the NOTICE is reproducible.
$headers = @{ "User-Agent" = "PostQuantum.Hybrid-fixture-fetch" }
$commit = (Invoke-RestMethod -Headers $headers "$repoApi/commits/master").sha
Write-Host "ACVP-Server master commit: $commit"

$sources = @(
    @{ Folder = "ML-KEM-keyGen-FIPS203";     ParameterSet = "ML-KEM-768"; Out = "ML-KEM-768-keyGen.json" },
    @{ Folder = "ML-KEM-encapDecap-FIPS203"; ParameterSet = "ML-KEM-768"; Out = "ML-KEM-768-encapDecap.json" },
    @{ Folder = "ML-DSA-keyGen-FIPS204";     ParameterSet = "ML-DSA-65";  Out = "ML-DSA-65-keyGen.json" },
    @{ Folder = "ML-DSA-sigVer-FIPS204";     ParameterSet = "ML-DSA-65";  Out = "ML-DSA-65-sigVer.json" }
)

foreach ($s in $sources) {
    $url = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/$commit/gen-val/json-files/$($s.Folder)/internalProjection.json"
    Write-Host "Fetching $url"
    $json = Invoke-RestMethod -Headers $headers $url

    $filtered = @($json.testGroups | Where-Object { $_.parameterSet -eq $s.ParameterSet })
    if ($filtered.Count -eq 0) {
        throw "No testGroups with parameterSet '$($s.ParameterSet)' in $($s.Folder) - schema change upstream?"
    }
    $json.testGroups = $filtered

    $outPath = Join-Path (Resolve-Path $fixtureDir).Path $s.Out
    # BOM-less UTF-8: Windows PowerShell 5.1's Out-File -Encoding utf8
    # writes a BOM, which strict JSON parsers reject.
    [System.IO.File]::WriteAllText(
        $outPath,
        ($json | ConvertTo-Json -Depth 100 -Compress),
        (New-Object System.Text.UTF8Encoding $false))
    $sizeKb = [math]::Round((Get-Item $outPath).Length / 1KB)
    Write-Host "  wrote $($s.Out) ($sizeKb KB, $($filtered.Count) test groups)"
}

$notice = @"
# NOTICE - NIST ACVP test vectors

The JSON files in this directory are filtered copies of the NIST ACVP
gen-val test vectors for FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA),
reduced to the ML-KEM-768 / ML-DSA-65 parameter sets.

- Source: https://github.com/usnistgov/ACVP-Server (gen-val/json-files)
- Commit: $commit
- Fetched: $(Get-Date -Format yyyy-MM-dd) by tools/fetch-nist-acvp.ps1

These files are works of the United States Government (NIST) and are not
subject to copyright protection in the United States (17 U.S.C. 105).
They are redistributed here unmodified except for filtering to the
parameter sets above. NIST does not endorse this project.
"@
$notice | Out-File -Encoding utf8 (Join-Path $fixtureDir "NOTICE.md")
Write-Host "wrote NOTICE.md"
