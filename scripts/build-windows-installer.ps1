<#
.SYNOPSIS
    Build the crowd-cast Windows installer (release binary + Inno Setup package).

.DESCRIPTION
    Compiles the release agent binary and runs the Inno Setup compiler (ISCC) on
    installer\windows\crowd-cast.iss to produce dist\crowd-cast-setup.exe.

    The upload endpoint is baked in at build time, so CROWD_CAST_API_GATEWAY_URL
    must be set (env var) or passed via -ApiGatewayUrl.

.EXAMPLE
    $env:CROWD_CAST_API_GATEWAY_URL = "https://.../prod/presign"
    pwsh scripts\build-windows-installer.ps1

.EXAMPLE
    pwsh scripts\build-windows-installer.ps1 -ApiGatewayUrl "https://.../prod/presign" -Version 1.0.3
#>
[CmdletBinding()]
param(
    [string]$ApiGatewayUrl = $env:CROWD_CAST_API_GATEWAY_URL,
    [string]$Version,
    [Parameter(Mandatory = $true)]
    [string]$Iscc,
    [Parameter(Mandatory = $true)]
    [string]$IsccSha256,
    [Parameter(Mandatory = $true)]
    [uri]$WinSparkleUrl,
    [Parameter(Mandatory = $true)]
    [string]$WinSparkleSha256,
    [Parameter(Mandatory = $true)]
    [UInt64]$WinSparkleSize
)

$ErrorActionPreference = 'Stop'
$repoRoot   = Split-Path -Parent $PSScriptRoot
$iss        = Join-Path $repoRoot 'installer\windows\crowd-cast.iss'
$releaseDir = Join-Path $repoRoot 'target\release'
$exePath    = Join-Path $releaseDir 'crowd-cast-agent.exe'
$obsDll     = Join-Path $releaseDir 'obs.dll'
$winSparkle = Join-Path $releaseDir 'WinSparkle.dll'

if ([string]::IsNullOrWhiteSpace($ApiGatewayUrl)) {
    throw "CROWD_CAST_API_GATEWAY_URL is required (set the env var or pass -ApiGatewayUrl)."
}

# Version: default to the [package] version in Cargo.toml.
if ([string]::IsNullOrWhiteSpace($Version)) {
    $line = Select-String -Path (Join-Path $repoRoot 'Cargo.toml') -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1
    if (-not $line) { throw "Could not read version from Cargo.toml." }
    $Version = $line.Matches[0].Groups[1].Value
}
# Inno's VersionInfoVersion needs a numeric x.y.z.b; strip any pre-release suffix.
$numeric = ($Version -split '[-+]')[0]
$parts = $numeric.Split('.')
while ($parts.Count -lt 4) { $parts += '0' }
$versionInfo = ($parts[0..3]) -join '.'

if (-not (Test-Path -LiteralPath $Iscc -PathType Leaf)) {
    throw "Exact ISCC.exe not found: $Iscc"
}
$IsccSha256 = $IsccSha256.Trim()
if ($IsccSha256 -cnotmatch '^[0-9a-f]{64}$') {
    throw 'ISCC SHA-256 must be 64 lowercase hexadecimal characters.'
}
$actualIsccSha256 = (Get-FileHash -LiteralPath $Iscc -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualIsccSha256 -cne $IsccSha256) {
    throw "ISCC SHA-256 mismatch: expected $IsccSha256, got $actualIsccSha256."
}

# Fetch the WinSparkle auto-update runtime; build.rs copies it next to the exe
# (target\release) so the installer can ship it.
Write-Host "==> Fetching WinSparkle..." -ForegroundColor Cyan
# Invoked as a PowerShell script (not an exe), so it throws on failure under
# $ErrorActionPreference='Stop'; don't gate on $LASTEXITCODE (only set by exes).
& (Join-Path $PSScriptRoot 'fetch-winsparkle.ps1') -Url $WinSparkleUrl -Sha256 $WinSparkleSha256 -Size $WinSparkleSize

Write-Host "==> Building release binary (v$Version)..." -ForegroundColor Cyan
$env:CROWD_CAST_API_GATEWAY_URL = $ApiGatewayUrl
& cargo build --release --locked
if ($LASTEXITCODE -ne 0) { throw "cargo build --release --locked failed." }
if (-not (Test-Path $exePath)) { throw "Expected binary not found at $exePath." }
# obs.dll is statically imported before Rust main and must exist for this build
# helper to complete. The release workflow remains fail-closed until the signed
# installer carries and verifies the entire exact OBS runtime closure.
if (-not (Test-Path $obsDll)) { throw "obs.dll not found at $obsDll (expected from the libobs-rs build)." }
# WinSparkle.dll is copied next to the exe by build.rs after fetch-winsparkle.
if (-not (Test-Path $winSparkle)) { throw "WinSparkle.dll not found at $winSparkle (run scripts/fetch-winsparkle.ps1)." }

Write-Host "==> Compiling installer (ISCC)..." -ForegroundColor Cyan
& $Iscc "/DAppVersion=$Version" "/DAppVersionInfo=$versionInfo" "/DSourceDir=$releaseDir" $iss
if ($LASTEXITCODE -ne 0) { throw "ISCC failed." }

$out = Join-Path $repoRoot "dist\crowd-cast-setup.exe"
if (-not (Test-Path -LiteralPath $out -PathType Leaf)) {
    throw "ISCC reported success but the installer was not produced: $out"
}
Write-Host "==> Installer built: $out" -ForegroundColor Green
