#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Gold-standard verification harness for every PostQuantum.Hybrid sample.
    Builds the solution, runs every sample on every target framework, and
    asserts each one's happy path, tamper-detection behavior, and
    analyzer-cleanliness all hold.

.DESCRIPTION
    What this script proves on a successful run:

      1. The full solution builds clean in Release with
         TreatWarningsAsErrors=true — so any analyzer warning
         (PQH001-PQH005) on a sample becomes a build error and fails
         this script before any sample is executed.

      2. Every sample exits 0.

      3. Every sample's stdout contains its expected happy-path /
         tamper-detection markers (no silent regressions where a
         "succeeds" sample skipped a code path).

      4. Every sample's combined stdout+stderr is free of unhandled-
         exception markers ("Unhandled exception", "fail: " ASP.NET
         failure logs, raw stack traces).

      5. Web samples actually serve traffic and return correctly-shaped
         responses to GET / POST endpoints.

      6. LargeFileEncryption produces a recovered file that SHA-256-
         diffs identical to a 200 KB random source.

      7. KeyRotationDemo proves zero-downtime rotation: an envelope
         sealed at v1 opens successfully before /rotate and returns
         HTTP 410 Gone after.

    Failed samples have their full captured output saved under
    <LogDir> for post-mortem.

.PARAMETER Tfms
    Target frameworks to exercise. Defaults to both net8.0 and net10.0.

.PARAMETER SkipWebApi
    Skip the two HTTP samples (WebApiDemo, KeyRotationDemo) — useful for
    environments where binding to localhost is blocked.

.PARAMETER WebApiPort
    Base port for the web samples. Defaults to 5099. Each sample uses
    WebApiPort + offset to avoid TIME_WAIT collisions on retry.

.PARAMETER LogDir
    Where to drop captured sample output on failure. Defaults to a fresh
    timestamped dir under the OS temp folder.

.PARAMETER CIMode
    Emit GitHub Actions ::error:: / ::group:: annotations as well as the
    normal Write-Host summary.

.EXAMPLE
    pwsh tools/run-all-samples.ps1
    pwsh tools/run-all-samples.ps1 -Tfms net10.0
    pwsh tools/run-all-samples.ps1 -SkipWebApi
    pwsh tools/run-all-samples.ps1 -CIMode
#>
[CmdletBinding()]
param(
    [string[]]$Tfms = @('net8.0', 'net10.0'),
    [switch]$SkipWebApi,
    [int]$WebApiPort = 5099,
    [string]$LogDir = (Join-Path ([System.IO.Path]::GetTempPath()) ("pqh-samples-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))),
    [switch]$CIMode
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Push-Location $RepoRoot
try {
    $script:results = New-Object System.Collections.Generic.List[object]
    $script:overallTimer = [System.Diagnostics.Stopwatch]::StartNew()

    # Patterns that indicate a sample crashed or emitted an uncaught
    # exception. The tamper-detection samples deliberately print
    # "rejected" / "failed" messages that we must NOT flag.
    $UnexpectedFailurePatterns = @(
        'Unhandled exception',
        '^fail:\s',
        '^\s+at .*\.\w+\(.*\) in .+:line \d+',  # stack frame from a .pdb
        'System\.NullReferenceException',
        'System\.ArgumentNullException'
    )

    function Test-UnexpectedFailure {
        param([string]$Output)
        if ([string]::IsNullOrEmpty($Output)) {
            return $null
        }
        foreach ($pattern in $UnexpectedFailurePatterns) {
            if ($Output -match $pattern) {
                return $Matches[0]
            }
        }
        return $null
    }

    function Save-FailureLog {
        param([string]$Sample, [string]$Tfm, [string]$Output)
        if (-not (Test-Path $LogDir)) {
            New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
        }
        $logPath = Join-Path $LogDir ("{0}-{1}.log" -f $Sample, $Tfm)
        Set-Content -Path $logPath -Value $Output -Encoding utf8
        return $logPath
    }

    function Record {
        param(
            [string]$Sample,
            [string]$Tfm,
            [bool]$Pass,
            [double]$ElapsedSec = 0.0,
            [string]$Detail = '',
            [string]$Output = ''
        )
        $savedLogPath = $null
        if (-not $Pass -and -not [string]::IsNullOrEmpty($Output)) {
            $savedLogPath = Save-FailureLog -Sample $Sample -Tfm $Tfm -Output $Output
        }
        $script:results.Add([pscustomobject]@{
            Sample      = $Sample
            Tfm         = $Tfm
            Pass        = $Pass
            ElapsedSec  = [math]::Round($ElapsedSec, 2)
            Detail      = $Detail
            Log         = $savedLogPath
        })
        $marker = if ($Pass) { 'PASS' } else { 'FAIL' }
        $color  = if ($Pass) { 'Green' } else { 'Red' }
        $line   = "[{0}] {1,-22} ({2,7}) {3,6:N2}s  {4}" -f $marker, $Sample, $Tfm, $ElapsedSec, $Detail
        Write-Host $line -ForegroundColor $color
        if ($CIMode -and -not $Pass) {
            $msg = "$Sample ($Tfm): $Detail"
            if ($savedLogPath) { $msg += " (log: $savedLogPath)" }
            Write-Host "::error title=Sample failed::$msg"
        }
    }

    function Invoke-SampleSimple {
        param(
            [string]$Project,
            [string]$Tfm,
            [string[]]$ExpectedSubstrings
        )
        $sample = Split-Path $Project -Leaf
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        # Capture stdout AND stderr together so an unhandled exception
        # (which writes to stderr) is visible to Test-UnexpectedFailure.
        $output = & dotnet run --project $Project --framework $Tfm --configuration Release --no-build 2>&1 | Out-String
        $exit = $LASTEXITCODE
        $sw.Stop()

        if ($exit -ne 0) {
            Record -Sample $sample -Tfm $Tfm -Pass $false -ElapsedSec $sw.Elapsed.TotalSeconds `
                -Detail "exit=$exit" -Output $output
            return
        }
        $unexpected = Test-UnexpectedFailure -Output $output
        if ($unexpected) {
            Record -Sample $sample -Tfm $Tfm -Pass $false -ElapsedSec $sw.Elapsed.TotalSeconds `
                -Detail "unexpected failure marker: '$unexpected'" -Output $output
            return
        }
        foreach ($needle in $ExpectedSubstrings) {
            if ($output -notmatch [regex]::Escape($needle)) {
                Record -Sample $sample -Tfm $Tfm -Pass $false -ElapsedSec $sw.Elapsed.TotalSeconds `
                    -Detail "missing expected output: '$needle'" -Output $output
                return
            }
        }
        Record -Sample $sample -Tfm $Tfm -Pass $true -ElapsedSec $sw.Elapsed.TotalSeconds
    }

    function Invoke-LargeFileEncryption {
        param([string]$Tfm)
        $sample = 'LargeFileEncryption'
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $work = Join-Path ([System.IO.Path]::GetTempPath()) ("pqh-lfe-test-" + [System.Guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Path $work -Force | Out-Null
        $combinedOut = ''
        try {
            $project = 'samples/LargeFileEncryption'
            $keyPrefix = Join-Path $work 'recipient'
            $plainPath = Join-Path $work 'plain.bin'
            $sealedPath = Join-Path $work 'sealed.bin'
            $recoveredPath = Join-Path $work 'recovered.bin'

            $rand = New-Object byte[] (200 * 1024)
            (New-Object System.Random 42).NextBytes($rand)
            [System.IO.File]::WriteAllBytes($plainPath, $rand)

            foreach ($cmd in @(
                @('gen', $keyPrefix),
                @('seal', "$keyPrefix.pub.pem", $plainPath, $sealedPath),
                @('open', "$keyPrefix.priv.pem", $sealedPath, $recoveredPath)
            )) {
                $step = $cmd[0]
                $stepOutput = & dotnet run --project $project --framework $Tfm --configuration Release --no-build -- @cmd 2>&1 | Out-String
                $combinedOut += "=== $step ===`n$stepOutput`n"
                if ($LASTEXITCODE -ne 0) {
                    $sw.Stop()
                    Record -Sample $sample -Tfm $Tfm -Pass $false -ElapsedSec $sw.Elapsed.TotalSeconds `
                        -Detail "$step exit=$LASTEXITCODE" -Output $combinedOut
                    return
                }
                $unexpected = Test-UnexpectedFailure -Output $stepOutput
                if ($unexpected) {
                    $sw.Stop()
                    Record -Sample $sample -Tfm $Tfm -Pass $false -ElapsedSec $sw.Elapsed.TotalSeconds `
                        -Detail "$step printed '$unexpected'" -Output $combinedOut
                    return
                }
            }

            $origHash  = (Get-FileHash $plainPath -Algorithm SHA256).Hash
            $recovHash = (Get-FileHash $recoveredPath -Algorithm SHA256).Hash
            $sw.Stop()
            if ($origHash -ne $recovHash) {
                Record -Sample $sample -Tfm $Tfm -Pass $false -ElapsedSec $sw.Elapsed.TotalSeconds `
                    -Detail "sha256 mismatch: orig=$($origHash.Substring(0,8)) recov=$($recovHash.Substring(0,8))" -Output $combinedOut
                return
            }
            $sealedSize = (Get-Item $sealedPath).Length
            Record -Sample $sample -Tfm $Tfm -Pass $true -ElapsedSec $sw.Elapsed.TotalSeconds `
                -Detail "200KB -> $sealedSize B sealed; SHA-256 round-trip OK"
        }
        finally {
            Remove-Item -Path $work -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    function Stop-StragglerProcesses {
        param([string]$NamePattern)
        Get-Process | Where-Object { $_.ProcessName -like $NamePattern } |
            ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
    }

    function Wait-ServerReady {
        param([string]$ProbeUrl, [int]$TimeoutMs = 15000)
        $deadline = (Get-Date).AddMilliseconds($TimeoutMs)
        while ((Get-Date) -lt $deadline) {
            try {
                $r = Invoke-WebRequest -Uri $ProbeUrl -UseBasicParsing -TimeoutSec 2
                if ($r.StatusCode -eq 200) { return $true }
            } catch { }
            Start-Sleep -Milliseconds 300
        }
        return $false
    }

    function Read-ServerLog {
        param([string]$LogPath)
        $combined = ''
        foreach ($p in @($LogPath, "$LogPath.err")) {
            if (Test-Path $p) {
                # The dotnet process still owns the file; open with
                # FileShare.ReadWrite so we don't fight it.
                try {
                    $fs = [System.IO.File]::Open($p, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                    $sr = New-Object System.IO.StreamReader($fs)
                    try {
                        $combined += "=== " + (Split-Path $p -Leaf) + " ===`n"
                        $combined += $sr.ReadToEnd() + "`n"
                    } finally {
                        $sr.Close()
                        $fs.Close()
                    }
                } catch {
                    $combined += "=== " + (Split-Path $p -Leaf) + " (read failed: $($_.Exception.Message)) ===`n"
                }
            }
        }
        return $combined
    }

    function Invoke-WebApiDemo {
        param([string]$Tfm, [int]$Port)
        $sample = 'WebApiDemo'
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        Stop-StragglerProcesses -NamePattern '*WebApiDemo*'

        $url = "http://localhost:$Port"
        $env:ASPNETCORE_URLS = $url
        $logPath = Join-Path ([System.IO.Path]::GetTempPath()) ("pqh-webapi-$Tfm.log")
        Remove-Item $logPath, "$logPath.err" -ErrorAction SilentlyContinue

        $proc = Start-Process -FilePath 'dotnet' -ArgumentList @(
            'run', '--project', 'samples/WebApiDemo',
            '--framework', $Tfm, '--configuration', 'Release', '--no-build',
            '--no-launch-profile'
        ) -PassThru -WindowStyle Hidden -RedirectStandardOutput $logPath -RedirectStandardError "$logPath.err"

        try {
            if (-not (Wait-ServerReady -ProbeUrl "$url/")) {
                $sw.Stop()
                $combined = Read-ServerLog -LogPath $logPath
                Record -Sample $sample -Tfm $Tfm -Pass $false -ElapsedSec $sw.Elapsed.TotalSeconds `
                    -Detail "server did not become ready within 15s" -Output $combined
                return
            }

            try {
                $kemPub  = Invoke-WebRequest -Uri "$url/pub/kem-public-key" -UseBasicParsing -TimeoutSec 5
                $kemBody = if ($kemPub.Content -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString($kemPub.Content) } else { [string]$kemPub.Content }
                if ($kemPub.StatusCode -ne 200 -or $kemBody -notmatch 'PQH HYBRID KEM PUBLIC KEY') {
                    Record -Sample $sample -Tfm $Tfm -Pass $false -ElapsedSec $sw.Elapsed.TotalSeconds `
                        -Detail "GET /pub/kem-public-key bad response" -Output (Read-ServerLog -LogPath $logPath)
                    return
                }
                $sigPub  = Invoke-WebRequest -Uri "$url/pub/sig-public-key" -UseBasicParsing -TimeoutSec 5
                $sigBody = if ($sigPub.Content -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString($sigPub.Content) } else { [string]$sigPub.Content }
                if ($sigPub.StatusCode -ne 200 -or $sigBody -notmatch 'PQH HYBRID SIG PUBLIC KEY') {
                    Record -Sample $sample -Tfm $Tfm -Pass $false -ElapsedSec $sw.Elapsed.TotalSeconds `
                        -Detail "GET /pub/sig-public-key bad response" -Output (Read-ServerLog -LogPath $logPath)
                    return
                }
                $sealResp = Invoke-WebRequest -Uri "$url/seal" -Method Post `
                    -Body (@{ Plaintext = 'hello pq world' } | ConvertTo-Json) `
                    -ContentType 'application/json' -UseBasicParsing -TimeoutSec 5
                $sealJson = ($sealResp.Content | ConvertFrom-Json)
                if (-not $sealJson.kemCiphertext -or -not $sealJson.ciphertext -or -not $sealJson.tag) {
                    Record -Sample $sample -Tfm $Tfm -Pass $false -ElapsedSec $sw.Elapsed.TotalSeconds `
                        -Detail "POST /seal missing fields" -Output (Read-ServerLog -LogPath $logPath)
                    return
                }
                $signResp = Invoke-WebRequest -Uri "$url/sign" -Method Post `
                    -Body (@{ Data = 'sign this' } | ConvertTo-Json) `
                    -ContentType 'application/json' -UseBasicParsing -TimeoutSec 5
                $signJson = ($signResp.Content | ConvertFrom-Json)
                if (-not $signJson.signature) {
                    Record -Sample $sample -Tfm $Tfm -Pass $false -ElapsedSec $sw.Elapsed.TotalSeconds `
                        -Detail "POST /sign missing signature" -Output (Read-ServerLog -LogPath $logPath)
                    return
                }
                $sw.Stop()
                # Final defense: scan the captured server log for unhandled-
                # exception markers that the HTTP responses might have hidden.
                $combined = Read-ServerLog -LogPath $logPath
                $unexpected = Test-UnexpectedFailure -Output $combined
                if ($unexpected) {
                    Record -Sample $sample -Tfm $Tfm -Pass $false -ElapsedSec $sw.Elapsed.TotalSeconds `
                        -Detail "server log contained unexpected failure marker: '$unexpected'" -Output $combined
                    return
                }
                Record -Sample $sample -Tfm $Tfm -Pass $true -ElapsedSec $sw.Elapsed.TotalSeconds `
                    -Detail "GET/POST round-trip OK"
            }
            catch {
                $sw.Stop()
                $combined = Read-ServerLog -LogPath $logPath
                Record -Sample $sample -Tfm $Tfm -Pass $false -ElapsedSec $sw.Elapsed.TotalSeconds `
                    -Detail "HTTP error: $($_.Exception.Message)" -Output $combined
                return
            }
        }
        finally {
            if ($proc -and -not $proc.HasExited) {
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            }
            Remove-Item $logPath, "$logPath.err" -ErrorAction SilentlyContinue
        }
    }

    function Invoke-KeyRotationDemo {
        param([string]$Tfm, [int]$Port)
        $sample = 'KeyRotationDemo'
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        Stop-StragglerProcesses -NamePattern '*KeyRotationDemo*'

        $url = "http://localhost:$Port"
        $env:ASPNETCORE_URLS = $url
        $logPath = Join-Path ([System.IO.Path]::GetTempPath()) ("pqh-krd-$Tfm.log")
        Remove-Item $logPath, "$logPath.err" -ErrorAction SilentlyContinue
        $keysDir = Join-Path ([System.IO.Path]::GetTempPath()) 'pqh-key-rotation-demo'
        if (Test-Path $keysDir) { Remove-Item -Path $keysDir -Recurse -Force -ErrorAction SilentlyContinue }

        $proc = Start-Process -FilePath 'dotnet' -ArgumentList @(
            'run', '--project', 'samples/KeyRotationDemo',
            '--framework', $Tfm, '--configuration', 'Release', '--no-build',
            '--no-launch-profile'
        ) -PassThru -WindowStyle Hidden -RedirectStandardOutput $logPath -RedirectStandardError "$logPath.err"

        try {
            if (-not (Wait-ServerReady -ProbeUrl "$url/health")) {
                $sw.Stop()
                $combined = Read-ServerLog -LogPath $logPath
                Record -Sample $sample -Tfm $Tfm -Pass $false -ElapsedSec $sw.Elapsed.TotalSeconds `
                    -Detail "server did not become ready" -Output $combined
                return
            }

            try {
                $keyResp = Invoke-WebRequest -Uri "$url/key" -UseBasicParsing -TimeoutSec 5
                $keyJson = ($keyResp.Content | ConvertFrom-Json)
                if ($keyJson.version -ne 1) {
                    Record -Sample $sample -Tfm $Tfm -Pass $false -ElapsedSec $sw.Elapsed.TotalSeconds `
                        -Detail "initial version was $($keyJson.version), expected 1" -Output (Read-ServerLog -LogPath $logPath)
                    return
                }

                $sealResp = Invoke-WebRequest -Uri "$url/seal" -Method Post `
                    -Body (@{ Plaintext = 'rotation demo test' } | ConvertTo-Json) `
                    -ContentType 'application/json' -UseBasicParsing -TimeoutSec 5
                $sealJson = ($sealResp.Content | ConvertFrom-Json)
                $envelope = $sealJson.envelope

                $openResp = Invoke-WebRequest -Uri "$url/open" -Method Post `
                    -Body (@{ Envelope = $envelope } | ConvertTo-Json) `
                    -ContentType 'application/json' -UseBasicParsing -TimeoutSec 5
                $openJson = ($openResp.Content | ConvertFrom-Json)
                if ($openJson.plaintext -ne 'rotation demo test') {
                    Record -Sample $sample -Tfm $Tfm -Pass $false -ElapsedSec $sw.Elapsed.TotalSeconds `
                        -Detail "open returned wrong plaintext" -Output (Read-ServerLog -LogPath $logPath)
                    return
                }

                $rotResp = Invoke-WebRequest -Uri "$url/rotate" -Method Post -UseBasicParsing -TimeoutSec 10
                $rotJson = ($rotResp.Content | ConvertFrom-Json)
                if (-not $rotJson.rotatedToVersion -or $rotJson.rotatedToVersion -le 1) {
                    Record -Sample $sample -Tfm $Tfm -Pass $false -ElapsedSec $sw.Elapsed.TotalSeconds `
                        -Detail "rotate did not advance version" -Output (Read-ServerLog -LogPath $logPath)
                    return
                }

                # Verify the old envelope returns 410 Gone. Use raw
                # HttpWebRequest so we can read the status on a 4xx
                # without PowerShell throwing on us.
                $staleStatus = 0
                $body = @{ Envelope = $envelope } | ConvertTo-Json
                $req = [System.Net.HttpWebRequest]::Create("$url/open")
                $req.Method = 'POST'
                $req.ContentType = 'application/json'
                $req.Timeout = 5000
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
                $req.ContentLength = $bytes.Length
                $stream = $req.GetRequestStream()
                $stream.Write($bytes, 0, $bytes.Length)
                $stream.Close()
                try {
                    $r = $req.GetResponse()
                    $staleStatus = [int]$r.StatusCode
                    $r.Close()
                } catch [System.Net.WebException] {
                    if ($_.Exception.Response) {
                        $staleStatus = [int]$_.Exception.Response.StatusCode
                    }
                }
                if ($staleStatus -ne 410) {
                    Record -Sample $sample -Tfm $Tfm -Pass $false -ElapsedSec $sw.Elapsed.TotalSeconds `
                        -Detail "stale open returned $staleStatus, expected 410 Gone" -Output (Read-ServerLog -LogPath $logPath)
                    return
                }
                $sw.Stop()

                # Final scan of the server log.
                $combined = Read-ServerLog -LogPath $logPath
                $unexpected = Test-UnexpectedFailure -Output $combined
                if ($unexpected) {
                    Record -Sample $sample -Tfm $Tfm -Pass $false -ElapsedSec $sw.Elapsed.TotalSeconds `
                        -Detail "server log contained unexpected failure marker: '$unexpected'" -Output $combined
                    return
                }
                Record -Sample $sample -Tfm $Tfm -Pass $true -ElapsedSec $sw.Elapsed.TotalSeconds `
                    -Detail "v1 seal/open + /rotate + stale-open 410 round-trip OK"
            }
            catch {
                $sw.Stop()
                $combined = Read-ServerLog -LogPath $logPath
                Record -Sample $sample -Tfm $Tfm -Pass $false -ElapsedSec $sw.Elapsed.TotalSeconds `
                    -Detail "HTTP error: $($_.Exception.Message)" -Output $combined
                return
            }
        }
        finally {
            if ($proc -and -not $proc.HasExited) {
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            }
            Remove-Item $logPath, "$logPath.err" -ErrorAction SilentlyContinue
            if (Test-Path $keysDir) { Remove-Item -Path $keysDir -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    # ----- Prerequisites + clean build -----
    if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
        throw "The 'dotnet' CLI is not on PATH. Install the .NET SDK and try again."
    }

    Write-Host ""
    Write-Host "==> Building solution in Release (TreatWarningsAsErrors=true)" -ForegroundColor Cyan
    Write-Host "    (any analyzer warning on a sample becomes a build error and fails this script)"
    $buildSw = [System.Diagnostics.Stopwatch]::StartNew()
    & dotnet build PostQuantum.Hybrid.slnx --configuration Release --nologo /v:minimal | Out-Null
    $buildExit = $LASTEXITCODE
    $buildSw.Stop()
    if ($buildExit -ne 0) {
        Write-Host "Release build failed (exit $buildExit) in $([math]::Round($buildSw.Elapsed.TotalSeconds, 1))s." -ForegroundColor Red
        if ($CIMode) { Write-Host "::error::Release build failed (exit $buildExit)" }
        throw "Release build failed; aborting samples run."
    }
    Write-Host "    build succeeded in $([math]::Round($buildSw.Elapsed.TotalSeconds, 1))s." -ForegroundColor Green

    # ----- Run every sample on every TFM -----
    foreach ($tfm in $Tfms) {
        Write-Host ""
        Write-Host "==> $tfm" -ForegroundColor Cyan
        if ($CIMode) { Write-Host "::group::$tfm" }

        Invoke-SampleSimple -Project 'samples/BasicDemo' -Tfm $tfm -ExpectedSubstrings @(
            'Hybrid KEM (X25519 + ML-KEM-768)',
            'Match: True',
            'Hybrid Signatures (Ed25519 + ML-DSA-65)',
            'Verify (good message): True',
            'Verify (tampered):     False'
        )

        Invoke-SampleSimple -Project 'samples/EnvelopesDemo' -Tfm $tfm -ExpectedSubstrings @(
            'Anonymous envelope',
            'Signed envelope',
            'Tampered envelope rejected'
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
            $tfmIdx = $Tfms.IndexOf($tfm)
            Invoke-WebApiDemo       -Tfm $tfm -Port ($WebApiPort + $tfmIdx)
            Invoke-KeyRotationDemo  -Tfm $tfm -Port ($WebApiPort + 100 + $tfmIdx)
        }

        if ($CIMode) { Write-Host "::endgroup::" }
    }

    # ----- Summary -----
    $script:overallTimer.Stop()
    Write-Host ""
    Write-Host "==> Summary  (total $([math]::Round($script:overallTimer.Elapsed.TotalSeconds, 1))s)" -ForegroundColor Cyan
    $script:results | Sort-Object Tfm, Sample | Format-Table Sample, Tfm, Pass, ElapsedSec, Detail -AutoSize | Out-String | Write-Host

    $failed = ($script:results | Where-Object { -not $_.Pass }).Count
    $passed = ($script:results | Where-Object { $_.Pass }).Count

    if ($failed -gt 0) {
        Write-Host "$failed of $($script:results.Count) sample runs FAILED." -ForegroundColor Red
        Write-Host "Failure logs were saved under: $LogDir" -ForegroundColor Yellow
        if ($CIMode) { Write-Host "::error::$failed of $($script:results.Count) sample runs failed" }
        exit 1
    }

    Write-Host "All $passed sample runs passed." -ForegroundColor Green
    # Remove the empty log dir we never wrote to.
    if ((Test-Path $LogDir) -and -not (Get-ChildItem $LogDir)) {
        Remove-Item $LogDir -ErrorAction SilentlyContinue
    }
    exit 0
}
finally {
    Pop-Location
}
