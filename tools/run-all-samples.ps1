#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Smoke-runs every sample in samples/ on every target framework
    (net8.0, net10.0) and asserts that each produces the expected output
    and exits 0.

.DESCRIPTION
    The non-interactive samples (BasicDemo, KemEncryption,
    SignedDocument, KeyPersistence, SecureMessenger) are launched with
    `dotnet run` and their stdout is grep'd for the success markers each
    sample prints when its happy path and tamper-detection step both
    work.

    LargeFileEncryption is a CLI; this script drives it through gen ->
    seal -> open and diffs the recovered file against the original.

    WebApiDemo starts a web server; this script starts it in the
    background, polls /, hits /pub/kem-public-key and POST /seal, and
    kills the process when done.

    Exit code is 0 if every sample on every TFM passes, otherwise 1
    with a per-sample summary printed at the end. Run from the repo
    root.

.EXAMPLE
    pwsh tools/run-all-samples.ps1
    pwsh tools/run-all-samples.ps1 -Tfms net10.0
    pwsh tools/run-all-samples.ps1 -SkipWebApi
#>
[CmdletBinding()]
param(
    [string[]]$Tfms = @('net8.0', 'net10.0'),
    [switch]$SkipWebApi,
    [int]$WebApiPort = 5099
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Push-Location $RepoRoot
try {
    $script:results = New-Object System.Collections.Generic.List[object]

    function Record {
        param([string]$Sample, [string]$Tfm, [bool]$Pass, [string]$Detail = '')
        $script:results.Add([pscustomobject]@{
            Sample = $Sample
            Tfm    = $Tfm
            Pass   = $Pass
            Detail = $Detail
        })
        $color = if ($Pass) { 'Green' } else { 'Red' }
        $marker = if ($Pass) { 'PASS' } else { 'FAIL' }
        Write-Host "[$marker] $Sample ($Tfm) $Detail" -ForegroundColor $color
    }

    function Invoke-SampleSimple {
        param(
            [string]$Project,
            [string]$Tfm,
            [string[]]$ExpectedSubstrings
        )
        $output = dotnet run --project $Project --framework $Tfm --configuration Release --no-build 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) {
            Record -Sample (Split-Path $Project -Leaf) -Tfm $Tfm -Pass $false -Detail "exit=$LASTEXITCODE"
            return
        }
        foreach ($needle in $ExpectedSubstrings) {
            if ($output -notmatch [regex]::Escape($needle)) {
                Record -Sample (Split-Path $Project -Leaf) -Tfm $Tfm -Pass $false -Detail "missing: '$needle'"
                return
            }
        }
        Record -Sample (Split-Path $Project -Leaf) -Tfm $Tfm -Pass $true
    }

    function Invoke-LargeFileEncryption {
        param([string]$Tfm)
        $work = Join-Path ([System.IO.Path]::GetTempPath()) ("pqh-lfe-test-" + [System.Guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Path $work -Force | Out-Null
        try {
            $project = 'samples/LargeFileEncryption'
            $keyPrefix = Join-Path $work 'recipient'
            $plainPath = Join-Path $work 'plain.bin'
            $sealedPath = Join-Path $work 'sealed.bin'
            $recoveredPath = Join-Path $work 'recovered.bin'

            # 200KB random payload — exercises multi-chunk path (chunkSize=64K).
            $rand = New-Object byte[] (200 * 1024)
            (New-Object System.Random 42).NextBytes($rand)
            [System.IO.File]::WriteAllBytes($plainPath, $rand)

            $gen = dotnet run --project $project --framework $Tfm --configuration Release --no-build -- gen $keyPrefix 2>&1 | Out-String
            if ($LASTEXITCODE -ne 0) {
                Record -Sample 'LargeFileEncryption' -Tfm $Tfm -Pass $false -Detail "gen exit=$LASTEXITCODE"
                return
            }
            $seal = dotnet run --project $project --framework $Tfm --configuration Release --no-build -- seal "$keyPrefix.pub.pem" $plainPath $sealedPath 2>&1 | Out-String
            if ($LASTEXITCODE -ne 0) {
                Record -Sample 'LargeFileEncryption' -Tfm $Tfm -Pass $false -Detail "seal exit=$LASTEXITCODE"
                return
            }
            $open = dotnet run --project $project --framework $Tfm --configuration Release --no-build -- open "$keyPrefix.priv.pem" $sealedPath $recoveredPath 2>&1 | Out-String
            if ($LASTEXITCODE -ne 0) {
                Record -Sample 'LargeFileEncryption' -Tfm $Tfm -Pass $false -Detail "open exit=$LASTEXITCODE"
                return
            }

            $origHash = (Get-FileHash $plainPath -Algorithm SHA256).Hash
            $recovHash = (Get-FileHash $recoveredPath -Algorithm SHA256).Hash
            if ($origHash -ne $recovHash) {
                Record -Sample 'LargeFileEncryption' -Tfm $Tfm -Pass $false -Detail "sha256 mismatch"
                return
            }
            $bytes = (Get-Item $sealedPath).Length
            Record -Sample 'LargeFileEncryption' -Tfm $Tfm -Pass $true -Detail "200KB -> $bytes B sealed, round-trip OK"
        }
        finally {
            Remove-Item -Path $work -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    function Invoke-WebApiDemo {
        param([string]$Tfm, [int]$Port)

        # Reap any straggler from a prior failed run — otherwise the new
        # build can't overwrite the locked exe.
        Get-Process | Where-Object { $_.ProcessName -like '*WebApiDemo*' } |
            ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }

        $url = "http://localhost:$Port"
        $env:ASPNETCORE_URLS = $url
        $logPath = Join-Path ([System.IO.Path]::GetTempPath()) ("pqh-webapi-$Tfm.log")

        $proc = Start-Process -FilePath 'dotnet' -ArgumentList @(
            'run', '--project', 'samples/WebApiDemo',
            '--framework', $Tfm, '--configuration', 'Release', '--no-build',
            '--no-launch-profile'
        ) -PassThru -WindowStyle Hidden -RedirectStandardOutput $logPath -RedirectStandardError "$logPath.err"

        try {
            $ready = $false
            for ($i = 0; $i -lt 30; $i++) {
                Start-Sleep -Milliseconds 500
                try {
                    $r = Invoke-WebRequest -Uri "$url/" -UseBasicParsing -TimeoutSec 2
                    if ($r.StatusCode -eq 200) {
                        $ready = $true
                        break
                    }
                }
                catch {
                    # not ready yet
                }
            }
            if (-not $ready) {
                Record -Sample 'WebApiDemo' -Tfm $Tfm -Pass $false -Detail "server did not become ready within 15s; log: $logPath"
                return
            }

            try {
                $kemPub = Invoke-WebRequest -Uri "$url/pub/kem-public-key" -UseBasicParsing -TimeoutSec 5
                $kemBody = if ($kemPub.Content -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString($kemPub.Content) } else { [string]$kemPub.Content }
                if ($kemPub.StatusCode -ne 200) {
                    Record -Sample 'WebApiDemo' -Tfm $Tfm -Pass $false -Detail "GET /pub/kem-public-key status=$($kemPub.StatusCode)"
                    return
                }
                if ($kemBody -notmatch 'PQH HYBRID KEM PUBLIC KEY') {
                    Record -Sample 'WebApiDemo' -Tfm $Tfm -Pass $false -Detail "GET /pub/kem-public-key content first 80: $($kemBody.Substring(0, [Math]::Min(80, $kemBody.Length)))"
                    return
                }
                $sigPub = Invoke-WebRequest -Uri "$url/pub/sig-public-key" -UseBasicParsing -TimeoutSec 5
                $sigBody = if ($sigPub.Content -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString($sigPub.Content) } else { [string]$sigPub.Content }
                if ($sigPub.StatusCode -ne 200) {
                    Record -Sample 'WebApiDemo' -Tfm $Tfm -Pass $false -Detail "GET /pub/sig-public-key status=$($sigPub.StatusCode)"
                    return
                }
                if ($sigBody -notmatch 'PQH HYBRID SIG PUBLIC KEY') {
                    Record -Sample 'WebApiDemo' -Tfm $Tfm -Pass $false -Detail "GET /pub/sig-public-key content first 80: $($sigBody.Substring(0, [Math]::Min(80, $sigBody.Length)))"
                    return
                }
                $sealResp = Invoke-WebRequest -Uri "$url/seal" -Method Post `
                    -Body (@{ Plaintext = 'hello pq world' } | ConvertTo-Json) `
                    -ContentType 'application/json' -UseBasicParsing -TimeoutSec 5
                $sealBody = if ($sealResp.Content -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString($sealResp.Content) } else { [string]$sealResp.Content }
                $sealJson = $sealBody | ConvertFrom-Json
                if (-not $sealJson.kemCiphertext -or -not $sealJson.ciphertext -or -not $sealJson.tag) {
                    Record -Sample 'WebApiDemo' -Tfm $Tfm -Pass $false -Detail "POST /seal missing fields; body: $($sealBody.Substring(0, [Math]::Min(120, $sealBody.Length)))"
                    return
                }
                $signResp = Invoke-WebRequest -Uri "$url/sign" -Method Post `
                    -Body (@{ Data = 'sign this' } | ConvertTo-Json) `
                    -ContentType 'application/json' -UseBasicParsing -TimeoutSec 5
                $signBody = if ($signResp.Content -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString($signResp.Content) } else { [string]$signResp.Content }
                $signJson = $signBody | ConvertFrom-Json
                if (-not $signJson.signature) {
                    Record -Sample 'WebApiDemo' -Tfm $Tfm -Pass $false -Detail "POST /sign missing signature; body: $($signBody.Substring(0, [Math]::Min(120, $signBody.Length)))"
                    return
                }

                Record -Sample 'WebApiDemo' -Tfm $Tfm -Pass $true -Detail "GET/POST round-trip OK"
            }
            catch {
                $logTail = ''
                if (Test-Path $logPath) {
                    $logTail = (Get-Content $logPath -Tail 20 -ErrorAction SilentlyContinue) -join '; '
                }
                Record -Sample 'WebApiDemo' -Tfm $Tfm -Pass $false -Detail "HTTP error: $($_.Exception.Message) | server: $logTail"
                return
            }
        }
        finally {
            if ($proc -and -not $proc.HasExited) {
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            }
            Remove-Item $logPath -ErrorAction SilentlyContinue
            Remove-Item "$logPath.err" -ErrorAction SilentlyContinue
        }
    }

    Write-Host ""
    Write-Host "==> Restoring + building samples in Release (once)..."
    dotnet build PostQuantum.Hybrid.slnx --configuration Release --nologo | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Release build failed; aborting."
    }

    foreach ($tfm in $Tfms) {
        Write-Host ""
        Write-Host "==> $tfm" -ForegroundColor Cyan

        Invoke-SampleSimple -Project 'samples/BasicDemo' -Tfm $tfm -ExpectedSubstrings @(
            'Hybrid KEM (X25519 + ML-KEM-768)',
            'Match: True',
            'Hybrid Signatures (Ed25519 + ML-DSA-65)',
            'Verify (good message): True',
            'Verify (tampered):     False'
        )

        Invoke-SampleSimple -Project 'samples/KemEncryption' -Tfm $tfm -ExpectedSubstrings @(
            'KEM -> AES-GCM encryption',
            'Tampered envelope rejected by AES-GCM'
        )

        Invoke-SampleSimple -Project 'samples/SignedDocument' -Tfm $tfm -ExpectedSubstrings @(
            'detached document signature',
            'signature valid for original document: True',
            'signature valid for tampered document: False'
        )

        Invoke-SampleSimple -Project 'samples/KeyPersistence' -Tfm $tfm -ExpectedSubstrings @(
            'PEM key persistence',
            'KEM round-trip: OK',
            'signature round-trip: OK'
        )

        Invoke-SampleSimple -Project 'samples/SecureMessenger' -Tfm $tfm -ExpectedSubstrings @(
            'signed + encrypted messaging',
            'the launch is approved for Friday',
            'Tampered packet rejected'
        )

        Invoke-LargeFileEncryption -Tfm $tfm

        if (-not $SkipWebApi) {
            Invoke-WebApiDemo -Tfm $tfm -Port ($WebApiPort + ($Tfms.IndexOf($tfm)))
        }
    }

    Write-Host ""
    Write-Host "==> Summary" -ForegroundColor Cyan
    $script:results | Format-Table Sample, Tfm, Pass, Detail -AutoSize

    $failed = ($script:results | Where-Object { -not $_.Pass }).Count
    if ($failed -gt 0) {
        Write-Host "$failed failure(s)." -ForegroundColor Red
        exit 1
    }
    Write-Host "All $($script:results.Count) sample runs passed." -ForegroundColor Green
    exit 0
}
finally {
    Pop-Location
}
