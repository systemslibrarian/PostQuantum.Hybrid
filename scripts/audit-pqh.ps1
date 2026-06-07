<#
.SYNOPSIS
Focused downstream hardening preflight for PostQuantum.Hybrid consumers.

.DESCRIPTION
This script checks a narrow, automatable subset of HARDENING-CHECKLIST.md:
- whether consumer projects reference PostQuantum.Hybrid analyzers,
- whether PQH001-PQH005 are enforced as build errors,
- whether dotnet reports known vulnerable packages,
- whether source files contain Export()/ExportPem() call sites that need
    manual logging/telemetry review,
- a small number of advisory heuristics for the checklist's safe-surface
    guidance.

It does NOT certify full hardening-checklist compliance. It cannot verify
protocol design, runtime smoke tests, safe key storage, logging sinks,
secret scanning, incident runbooks, or other operational controls.

.EXAMPLE
.\audit-pqh.ps1 -Path .

.EXAMPLE
.\audit-pqh.ps1 -Path .\MyApp.slnx

.EXAMPLE
.\audit-pqh.ps1 -Path . -IncludeNonProductionCode

.NOTES
Exit code 0: no automatic failures; manual review items may still exist.
Exit code 1: one or more automatic controls failed.
Exit code 2: the preflight could not prove one or more controls.
Examples assume you are invoking a local copy named `audit-pqh.ps1`.
The script can live in any directory your team uses for internal tooling.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$Path = ".",

    [Parameter(Mandatory = $false)]
    [switch]$IncludeNonProductionCode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$consumerLibraries = @(
    "PostQuantum.Hybrid",
    "PostQuantum.Hybrid.Envelopes",
    "PostQuantum.Hybrid.AspNetCore"
)

$requiredRules = @(
    "PQH001",
    "PQH002",
    "PQH003",
    "PQH004",
    "PQH005"
)

function ConvertTo-ItemArray {
    param([object]$Value)

    if ($null -eq $Value) {
        return @()
    }

    if ($Value -is [System.Array]) {
        return $Value
    }

    return @($Value)
}

function Get-RelativeDisplayPath {
    param(
        [string]$BasePath,
        [string]$ChildPath
    )

    $normalizedBase = [System.IO.Path]::GetFullPath($BasePath).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
    $normalizedChild = [System.IO.Path]::GetFullPath($ChildPath)
    $prefix = $normalizedBase + [System.IO.Path]::DirectorySeparatorChar

    if ($normalizedChild.Equals($normalizedBase, [System.StringComparison]::OrdinalIgnoreCase)) {
        return [System.IO.Path]::GetFileName($normalizedChild)
    }

    if ($normalizedChild.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $normalizedChild.Substring($prefix.Length)
    }

    return $normalizedChild
}

function Get-ResolvedTargetInfo {
    param([string]$InputPath)

    $resolvedPath = Resolve-Path -LiteralPath $InputPath | Select-Object -ExpandProperty Path
    $item = Get-Item -LiteralPath $resolvedPath

    return [pscustomobject]@{
        Path          = $resolvedPath
        IsDirectory   = $item.PSIsContainer
        BaseDirectory = if ($item.PSIsContainer) { $resolvedPath } else { [System.IO.Path]::GetDirectoryName($resolvedPath) }
        Extension     = if ($item.PSIsContainer) { "" } else { $item.Extension.ToLowerInvariant() }
    }
}

function Get-FilteredChildItems {
    param(
        [string]$Root,
        [string]$Filter
    )

    return @(Get-ChildItem -Path $Root -Recurse -Filter $Filter -File | Where-Object {
            $_.FullName -notmatch '[\\/](bin|obj)[\\/]'
        })
}

function Invoke-DotnetJson {
    param([string[]]$Arguments)

    $output = (& dotnet @Arguments 2>&1 | Out-String)
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        return [pscustomobject]@{
            Success = $false
            Output  = $output.Trim()
            Data    = $null
        }
    }

    try {
        $parsed = $output | ConvertFrom-Json -ErrorAction Stop
        return [pscustomobject]@{
            Success = $true
            Output  = $output.Trim()
            Data    = $parsed
        }
    }
    catch {
        return [pscustomobject]@{
            Success = $false
            Output  = $output.Trim()
            Data    = $null
        }
    }
}

function Get-IdentityValues {
    param(
        [object]$Items,
        [string]$PropertyName
    )

    $values = @()

    foreach ($item in (ConvertTo-ItemArray $Items)) {
        if ($null -ne $item.PSObject.Properties[$PropertyName]) {
            $value = [string]$item.$PropertyName
            if (-not [string]::IsNullOrWhiteSpace($value)) {
                $values += $value
            }
        }
    }

    return $values
}

function Get-ProjectSnapshot {
    param([string]$ProjectPath)

    return Invoke-DotnetJson -Arguments @(
        "msbuild",
        $ProjectPath,
        "-nologo",
        "-getProperty:IsTestProject",
        "-getProperty:OutputType",
        "-getProperty:UsingMicrosoftNETSdkWeb",
        "-getProperty:TreatWarningsAsErrors",
        "-getProperty:WarningsAsErrors",
        "-getItem:PackageReference",
        "-getItem:ProjectReference"
    )
}

function Get-ProjectCategory {
    param(
        [string]$ProjectPath,
        [pscustomobject]$Snapshot
    )

    $normalizedPath = [System.IO.Path]::GetFullPath($ProjectPath)
    $isTestProject = [string]$Snapshot.Data.Properties.IsTestProject

    if ($isTestProject.Trim().ToLowerInvariant() -eq "true" -or $normalizedPath -match '[\\/]tests[\\/]') {
        return "test"
    }

    if ($normalizedPath -match '[\\/]samples[\\/]') {
        return "sample"
    }

    if ($normalizedPath -match '[\\/]templates[\\/]') {
        return "template"
    }

    if ($normalizedPath -match '[\\/]benchmarks[\\/]') {
        return "benchmark"
    }

    if ($normalizedPath -match '[\\/]fuzz[\\/]') {
        return "fuzz"
    }

    return "production"
}

function Get-ProjectSourceFacts {
    param(
        [string]$ProjectDirectory,
        [string]$BaseDirectory
    )

    $facts = [ordered]@{
        HasAddPostQuantumHybrid = $false
        AddPostQuantumHybridLocation = ""
        HasAddRotatingHybridKemKeys = $false
        AddRotatingHybridKemKeysLocation = ""
        HasEnvelopeUsage = $false
        EnvelopeUsageLocation = ""
        HasManualKemUsage = $false
        ManualKemUsageLocation = ""
    }

    foreach ($sourceFile in (Get-FilteredChildItems -Root $ProjectDirectory -Filter "*.cs")) {
        $displayPath = Get-RelativeDisplayPath -BasePath $BaseDirectory -ChildPath $sourceFile.FullName
        $lines = Get-Content -LiteralPath $sourceFile.FullName

        for ($lineIndex = 0; $lineIndex -lt $lines.Count; $lineIndex++) {
            $line = $lines[$lineIndex]
            $location = "${displayPath}:$($lineIndex + 1)"

            if (-not $facts.HasAddPostQuantumHybrid -and $line -match '\bAddPostQuantumHybrid\s*\(') {
                $facts.HasAddPostQuantumHybrid = $true
                $facts.AddPostQuantumHybridLocation = $location
            }

            if (-not $facts.HasAddRotatingHybridKemKeys -and $line -match '\bAddRotatingHybridKemKeys\s*\(') {
                $facts.HasAddRotatingHybridKemKeys = $true
                $facts.AddRotatingHybridKemKeysLocation = $location
            }

            if (-not $facts.HasEnvelopeUsage -and ($line -match '\bHybridEnvelope\.' -or $line -match '\bSignedHybridEnvelope\.')) {
                $facts.HasEnvelopeUsage = $true
                $facts.EnvelopeUsageLocation = $location
            }

            if (-not $facts.HasManualKemUsage -and $line -match '\bHybridKem\.(Encapsulate|Decapsulate|TryDecapsulate)\s*\(') {
                $facts.HasManualKemUsage = $true
                $facts.ManualKemUsageLocation = $location
            }
        }
    }

    return [pscustomobject]$facts
}

function Get-ConsumerReferences {
    param([pscustomobject]$Snapshot)

    $packageNames = Get-IdentityValues -Items $Snapshot.Data.Items.PackageReference -PropertyName "Identity"
    $projectNames = Get-IdentityValues -Items $Snapshot.Data.Items.ProjectReference -PropertyName "Filename"
    $allReferences = @($packageNames + $projectNames)

    return @($consumerLibraries | Where-Object { $allReferences -contains $_ })
}

function Test-AnalyzerInstalled {
    param([pscustomobject]$Snapshot)

    $packageNames = Get-IdentityValues -Items $Snapshot.Data.Items.PackageReference -PropertyName "Identity"
    $projectNames = Get-IdentityValues -Items $Snapshot.Data.Items.ProjectReference -PropertyName "Filename"

    return ($packageNames -contains "PostQuantum.Hybrid.Analyzers") -or ($projectNames -contains "PostQuantum.Hybrid.Analyzers")
}

function Test-WarningsAsErrors {
    param([pscustomobject]$Snapshot)

    $treatWarningsAsErrors = [string]$Snapshot.Data.Properties.TreatWarningsAsErrors
    if ($treatWarningsAsErrors.Trim().ToLowerInvariant() -eq "true") {
        return [pscustomobject]@{
            Passed = $true
            Reason = "TreatWarningsAsErrors=true"
        }
    }

    $warningsAsErrors = [string]$Snapshot.Data.Properties.WarningsAsErrors
    $tokens = @()

    foreach ($token in ($warningsAsErrors -split '[;,\s]')) {
        $trimmed = $token.Trim()
        if (-not [string]::IsNullOrWhiteSpace($trimmed)) {
            $tokens += $trimmed
        }
    }

    $missingRules = @($requiredRules | Where-Object { $tokens -notcontains $_ })

    return [pscustomobject]@{
        Passed = ($missingRules.Count -eq 0)
        Reason = if ($missingRules.Count -eq 0) {
            "WarningsAsErrors contains PQH001-PQH005"
        }
        else {
            "Missing from WarningsAsErrors: $($missingRules -join ', ')"
        }
    }
}

function Add-VulnerabilityRecords {
    param(
        [object]$Node,
        [System.Collections.ArrayList]$Results
    )

    if ($null -eq $Node) {
        return
    }

    if ($Node -is [System.Array]) {
        foreach ($entry in $Node) {
            Add-VulnerabilityRecords -Node $entry -Results $Results
        }
        return
    }

    if ($Node -is [System.ValueType] -or $Node -is [string]) {
        return
    }

    if ($null -ne $Node.PSObject.Properties['vulnerabilities'] -and $null -ne $Node.vulnerabilities) {
        $packageId = if ($null -ne $Node.PSObject.Properties['id']) { [string]$Node.id } else { "(unknown package)" }

        foreach ($vulnerability in (ConvertTo-ItemArray $Node.vulnerabilities)) {
            $null = $Results.Add([pscustomobject]@{
                    PackageId   = $packageId
                    Severity    = if ($null -ne $vulnerability.PSObject.Properties['severity']) { [string]$vulnerability.severity } else { "unknown" }
                    AdvisoryUrl = if ($null -ne $vulnerability.PSObject.Properties['advisoryurl']) { [string]$vulnerability.advisoryurl } else { "" }
                })
        }
    }

    foreach ($property in $Node.PSObject.Properties) {
        if ($property.Name -ne 'vulnerabilities') {
            Add-VulnerabilityRecords -Node $property.Value -Results $Results
        }
    }
}

function Get-VulnerabilityRecords {
    param([object]$JsonObject)

    $results = New-Object System.Collections.ArrayList
    Add-VulnerabilityRecords -Node $JsonObject -Results $results
    return @($results)
}

function Get-VulnerabilityScanTargets {
    param(
        [pscustomobject]$TargetInfo,
        [string[]]$ConsumerProjectPaths
    )

    if (-not $TargetInfo.IsDirectory) {
        if ($TargetInfo.Extension -in @('.sln', '.slnx', '.csproj')) {
            return @($TargetInfo.Path)
        }

        throw "Path must point to a directory, .sln, .slnx, or .csproj file."
    }

    $solutionTargets = @(Get-FilteredChildItems -Root $TargetInfo.BaseDirectory -Filter "*.slnx")
    if ($solutionTargets.Count -eq 0) {
        $solutionTargets = @(Get-FilteredChildItems -Root $TargetInfo.BaseDirectory -Filter "*.sln")
    }

    if ($solutionTargets.Count -eq 1) {
        return @($solutionTargets[0].FullName)
    }

    if ($ConsumerProjectPaths.Count -gt 0) {
        return @($ConsumerProjectPaths)
    }

    return @()
}

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    Write-Host "[FAIL] The dotnet CLI is required to run this preflight." -ForegroundColor Red
    exit 2
}

$targetInfo = Get-ResolvedTargetInfo -InputPath $Path
$automaticFailures = 0
$exportReviewItems = 0
$heuristicReviewItems = 0
$inconclusive = 0
$consumerProjectInfos = @()

$explicitProjectTarget = (-not $targetInfo.IsDirectory) -and $targetInfo.Extension -eq '.csproj'

Write-Host "[*] PostQuantum.Hybrid hardening preflight" -ForegroundColor Cyan
Write-Host "Target: $($targetInfo.Path)"
Write-Host "This script checks only a subset of HARDENING-CHECKLIST.md.`n"

$projectFiles = @(if ($targetInfo.IsDirectory) {
    Get-FilteredChildItems -Root $targetInfo.BaseDirectory -Filter "*.csproj"
}
elseif ($targetInfo.Extension -eq '.csproj') {
    @((Get-Item -LiteralPath $targetInfo.Path))
}
else {
    @()
})

if ($projectFiles.Count -eq 0) {
    Write-Host "[WARN] No .csproj files were found beneath the target." -ForegroundColor DarkYellow
    exit 2
}

foreach ($project in $projectFiles) {
    $snapshot = Get-ProjectSnapshot -ProjectPath $project.FullName
    $displayPath = Get-RelativeDisplayPath -BasePath $targetInfo.BaseDirectory -ChildPath $project.FullName

    if (-not $snapshot.Success) {
        Write-Host "[WARN] Could not evaluate $displayPath with dotnet msbuild." -ForegroundColor DarkYellow
        $inconclusive++
        continue
    }

    $consumerReferences = @(Get-ConsumerReferences -Snapshot $snapshot)
    if ($consumerReferences.Count -eq 0) {
        continue
    }

    $outputType = [string]$snapshot.Data.Properties.OutputType
    $usingWebSdk = [string]$snapshot.Data.Properties.UsingMicrosoftNETSdkWeb
    $category = Get-ProjectCategory -ProjectPath $project.FullName -Snapshot $snapshot

    $consumerProjectInfos += [pscustomobject]@{
        FullName = $project.FullName
        DisplayPath = $displayPath
        ProjectDirectory = [System.IO.Path]::GetDirectoryName($project.FullName)
        ConsumerReferences = $consumerReferences
        Category = $category
        OutputType = $outputType
        UsesWebSdk = ($usingWebSdk.Trim().ToLowerInvariant() -eq "true")
        IsApplicationProject = ($outputType -eq "Exe") -or ($usingWebSdk.Trim().ToLowerInvariant() -eq "true")
    }

    Write-Host "Auditing $displayPath" -ForegroundColor Yellow
    Write-Host "  Uses: $($consumerReferences -join ', ')"
    Write-Host "  Category: $category" -ForegroundColor DarkGray

    if (Test-AnalyzerInstalled -Snapshot $snapshot) {
        Write-Host "  [PASS] Analyzer reference present." -ForegroundColor Green
    }
    else {
        Write-Host "  [FAIL] Missing PostQuantum.Hybrid.Analyzers reference." -ForegroundColor Red
        $automaticFailures++
    }

    $warningsCheck = Test-WarningsAsErrors -Snapshot $snapshot
    if ($warningsCheck.Passed) {
        Write-Host "  [PASS] PQH rules are configured as build errors ($($warningsCheck.Reason))." -ForegroundColor Green
    }
    else {
        Write-Host "  [FAIL] PQH001-PQH005 are not all enforced as build errors. $($warningsCheck.Reason)." -ForegroundColor Red
        $automaticFailures++
    }
}

if ($consumerProjectInfos.Count -eq 0) {
    Write-Host "[WARN] No consumer projects referencing PostQuantum.Hybrid, PostQuantum.Hybrid.Envelopes, or PostQuantum.Hybrid.AspNetCore were found." -ForegroundColor DarkYellow
    exit 2
}

Write-Host "`n[*] Running vulnerability scan..." -ForegroundColor Yellow
$scanTargets = @(Get-VulnerabilityScanTargets -TargetInfo $targetInfo -ConsumerProjectPaths @($consumerProjectInfos | ForEach-Object { $_.FullName }))

if ($scanTargets.Count -eq 0) {
    Write-Host "  [WARN] No solution or consumer project was available for vulnerability scanning." -ForegroundColor DarkYellow
    $inconclusive++
}
else {
    foreach ($scanTarget in $scanTargets) {
        $scanDisplayPath = Get-RelativeDisplayPath -BasePath $targetInfo.BaseDirectory -ChildPath $scanTarget
        $scanResult = Invoke-DotnetJson -Arguments @(
            "list",
            $scanTarget,
            "package",
            "--vulnerable",
            "--include-transitive",
            "--format",
            "json"
        )

        if (-not $scanResult.Success) {
            Write-Host "  [WARN] Vulnerability scan could not be evaluated for $scanDisplayPath." -ForegroundColor DarkYellow
            $inconclusive++
            continue
        }

        $vulnerabilities = @(Get-VulnerabilityRecords -JsonObject $scanResult.Data)
        if ($vulnerabilities.Count -eq 0) {
            Write-Host "  [PASS] No vulnerable packages reported for $scanDisplayPath." -ForegroundColor Green
            continue
        }

        Write-Host "  [FAIL] Vulnerable packages were reported for $scanDisplayPath." -ForegroundColor Red
        foreach ($record in ($vulnerabilities | Sort-Object PackageId, Severity -Unique)) {
            $suffix = if ([string]::IsNullOrWhiteSpace($record.AdvisoryUrl)) { "" } else { " ($($record.AdvisoryUrl))" }
            Write-Host "         $($record.PackageId) [$($record.Severity)]$suffix" -ForegroundColor Red
        }
        $automaticFailures++
    }
}

Write-Host "`n[*] Running safe-surface heuristics..." -ForegroundColor Yellow
$heuristicProjects = @(if ($IncludeNonProductionCode -or $explicitProjectTarget) {
    $consumerProjectInfos
}
else {
    $consumerProjectInfos | Where-Object { $_.Category -eq 'production' }
})

foreach ($projectInfo in $heuristicProjects) {
    if (-not $projectInfo.IsApplicationProject) {
        continue
    }

    $facts = Get-ProjectSourceFacts -ProjectDirectory $projectInfo.ProjectDirectory -BaseDirectory $targetInfo.BaseDirectory

    if (($projectInfo.ConsumerReferences -contains 'PostQuantum.Hybrid.AspNetCore') -and
        -not ($facts.HasAddPostQuantumHybrid -or $facts.HasAddRotatingHybridKemKeys)) {
        Write-Host "  [REVIEW] $($projectInfo.DisplayPath): no AddPostQuantumHybrid(...) or AddRotatingHybridKemKeys(...) call was found under this project root." -ForegroundColor DarkYellow
        Write-Host "           If you use an equivalent abstraction, keep the justification with your hardening evidence." -ForegroundColor DarkGray
        $heuristicReviewItems++
    }

    if (($projectInfo.ConsumerReferences -contains 'PostQuantum.Hybrid') -and
        $facts.HasManualKemUsage -and
        -not $facts.HasEnvelopeUsage) {
        Write-Host "  [REVIEW] $($projectInfo.DisplayPath): manual HybridKem flow detected at $($facts.ManualKemUsageLocation)." -ForegroundColor DarkYellow
        Write-Host "           If this app only needs seal/open semantics, prefer PostQuantum.Hybrid.Envelopes over hand-rolled KEM + AEAD glue." -ForegroundColor DarkGray
        $heuristicReviewItems++
    }
}

if ($heuristicReviewItems -eq 0) {
    Write-Host "  [PASS] No safe-surface heuristic issues were found in the scanned project roots." -ForegroundColor Green
}
else {
    Write-Host "  [WARN] Found $heuristicReviewItems safe-surface heuristic review item(s)." -ForegroundColor DarkYellow
}

Write-Host "`n[*] Checking for Export()/ExportPem() call sites that require manual review..." -ForegroundColor Yellow
$exportReviewProjects = @(if ($IncludeNonProductionCode -or $explicitProjectTarget) {
    $consumerProjectInfos
}
else {
    $consumerProjectInfos | Where-Object { $_.Category -eq 'production' }
})

if (-not $IncludeNonProductionCode -and -not $explicitProjectTarget) {
    $skippedProjects = @($consumerProjectInfos | Where-Object { $_.Category -ne 'production' })
    if ($skippedProjects.Count -gt 0) {
        $skippedSummary = $skippedProjects |
            Group-Object Category |
            Sort-Object Name |
            ForEach-Object { "$($_.Name)=$($_.Count)" }
        Write-Host "  [INFO] Skipping non-production projects by default: $($skippedSummary -join ', '). Use -IncludeNonProductionCode to include them." -ForegroundColor DarkGray
    }
}

if ($exportReviewProjects.Count -eq 0) {
    Write-Host "  [WARN] No project roots were selected for export-call review." -ForegroundColor DarkYellow
    $inconclusive++
}
else {
    $checkedFiles = @()
    foreach ($projectInfo in $exportReviewProjects) {
        $checkedFiles += Get-FilteredChildItems -Root $projectInfo.ProjectDirectory -Filter "*.cs"
    }

    $checkedFiles = @($checkedFiles | Sort-Object FullName -Unique)

    foreach ($sourceFile in $checkedFiles) {
        $lines = Get-Content -LiteralPath $sourceFile.FullName

        for ($lineIndex = 0; $lineIndex -lt $lines.Count; $lineIndex++) {
            if ($lines[$lineIndex] -match '\.Export\(\)' -or $lines[$lineIndex] -match '\.ExportPem\(\)') {
                $displayPath = Get-RelativeDisplayPath -BasePath $targetInfo.BaseDirectory -ChildPath $sourceFile.FullName
                Write-Host "  [REVIEW] ${displayPath}:$($lineIndex + 1)" -ForegroundColor DarkYellow
                Write-Host "           $($lines[$lineIndex].Trim())" -ForegroundColor DarkGray
                $exportReviewItems++
            }
        }
    }
}

if ($exportReviewItems -eq 0) {
    Write-Host "  [PASS] No Export()/ExportPem() call sites were found under the reviewed project roots." -ForegroundColor Green
}
else {
    Write-Host "  [WARN] Found $exportReviewItems Export()/ExportPem() call site(s). Review them for logging, telemetry, and exception leaks." -ForegroundColor DarkYellow
}

Write-Host "`nSummary" -ForegroundColor Cyan
Write-Host "  Automatic failures : $automaticFailures"
Write-Host "  Heuristic review items: $heuristicReviewItems"
Write-Host "  Export review items   : $exportReviewItems"
Write-Host "  Inconclusive checks : $inconclusive"

if ($automaticFailures -gt 0) {
    Write-Host "`n[FAIL] The preflight found automatic control failures." -ForegroundColor Red
    exit 1
}

if ($inconclusive -gt 0) {
    Write-Host "`n[WARN] The preflight could not prove all targeted controls. Treat this as incomplete evidence, not a pass." -ForegroundColor DarkYellow
    exit 2
}

if (($heuristicReviewItems + $exportReviewItems) -gt 0) {
    Write-Host "`n[WARN] The automated checks passed, but manual review is still required for the heuristic and export-review items listed above." -ForegroundColor DarkYellow
    exit 0
}

Write-Host "`n[PASS] The automated preflight checks passed. This is supporting evidence for a subset of the hardening checklist, not a full compliance certificate." -ForegroundColor Green
exit 0
