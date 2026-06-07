[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [string]$Path = "."
)

$target = Resolve-Path $Path | Select-Object -ExpandProperty Path
$failed = $false

Write-Host "[*] PostQuantum.Hybrid Hardening Audit" -ForegroundColor Cyan
Write-Host "Scanning projects in: $target`n"

$projects = Get-ChildItem -Path $target -Recurse -Filter "*.csproj"
if ($projects.Count -eq 0) {
    Write-Host "No .csproj files found in $target." -ForegroundColor Red
    exit 1
}

foreach ($proj in $projects) {
    $content = Get-Content $proj.FullName -Raw
    
    if (-not ($content -match "PostQuantum\.Hybrid")) {
        continue
    }

    Write-Host "Auditing $($proj.Name)" -ForegroundColor Yellow

    if ($content -match 'PackageReference Include="PostQuantum\.Hybrid"' -and $content -notmatch 'PackageReference Include="PostQuantum\.Hybrid\.Analyzers"') {
        Write-Host "  [FAIL] Missing PostQuantum.Hybrid.Analyzers package." -ForegroundColor Red
        $failed = $true
    } else {
        Write-Host "  [PASS] Analyzers installed." -ForegroundColor Green
    }

    $hasGlobalWarningsAsErrors = $content -match "TreatWarningsAsErrors>true"
    $hasSpecificWarningsAsErrors = $content -match "WarningsAsErrors>[^<]*PQH001"
    
    if (-not $hasGlobalWarningsAsErrors -and -not $hasSpecificWarningsAsErrors) {
        Write-Host "  [FAIL] PQH001-PQH005 are not strictly enforced." -ForegroundColor Red
        $failed = $true
    } else {
        Write-Host "  [PASS] Security rules are enforced as errors." -ForegroundColor Green
    }
}

Write-Host "`n[*] Running vulnerable package scan..." -ForegroundColor Yellow
$vulnOutput = dotnet list $target package --vulnerable 2>&1
if ($vulnOutput -match "has the following vulnerable packages") {
    Write-Host "  [FAIL] Vulnerable packages found!" -ForegroundColor Red
    $failed = $true
} else {
    Write-Host "  [PASS] Clean dependency tree." -ForegroundColor Green
}

Write-Host "`n[*] Checking for manually verifiable key export risks..." -ForegroundColor Yellow
$csFiles = Get-ChildItem -Path $target -Recurse -Filter "*.cs"
$exportWarnings = 0

foreach ($cs in $csFiles) {
    if ($cs.FullName -match "obj\\" -or $cs.FullName -match "bin\\") { continue }
    
    $lines = Get-Content $cs.FullName
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match "\.Export\(\)" -or $lines[$i] -match "\.ExportPem\(\)") {
            Write-Host "  [ACTION REQUIRED] Key export found at $($cs.Name):$($i+1)" -ForegroundColor DarkYellow
            $exportWarnings++
        }
    }
}

if ($exportWarnings -eq 0) {
    Write-Host "  [PASS] No explicit key exports found." -ForegroundColor Green
} else {
    Write-Host "  [WARN] Found $exportWarnings manual audit item(s)." -ForegroundColor DarkYellow
}

Write-Host ""
if ($failed) {
    Write-Host "[FAIL] Audit failed. Please fix broken controls." -ForegroundColor Red
    exit 1
} elseif ($exportWarnings -gt 0) {
    Write-Host "[WARN] Audit passed technically, but manual exports found." -ForegroundColor DarkYellow
    exit 0
} else {
    Write-Host "[PASS] Audit passed fully." -ForegroundColor Green
    exit 0
}
