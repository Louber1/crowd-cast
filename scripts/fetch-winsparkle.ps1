[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [uri]$Url,
    [Parameter(Mandatory = $true)]
    [string]$Sha256,
    [Parameter(Mandatory = $true)]
    [UInt64]$Size
)

$ErrorActionPreference = 'Stop'
$Version = '0.9.3'
$Sha256 = $Sha256.Trim()
if ($Url.Scheme -ne 'https' -or -not [string]::IsNullOrEmpty($Url.UserInfo) -or -not [string]::IsNullOrEmpty($Url.Query) -or -not [string]::IsNullOrEmpty($Url.Fragment)) {
    throw 'WinSparkle URL must be HTTPS without credentials, query, or fragment.'
}
if ($Sha256 -cnotmatch '^[0-9a-f]{64}$') {
    throw 'WinSparkle SHA-256 must be 64 lowercase hexadecimal characters.'
}
if ($Size -eq 0) {
    throw 'WinSparkle archive size must be non-zero.'
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$destDir = Join-Path $repoRoot "build\winsparkle\$Version"
$work = Join-Path ([System.IO.Path]::GetTempPath()) "crowd-cast-winsparkle-$([guid]::NewGuid().ToString('N'))"
$archive = Join-Path $work 'winsparkle.zip'
$extract = Join-Path $work 'extract'
$stage = Join-Path (Split-Path -Parent $destDir) "$Version.stage-$([guid]::NewGuid().ToString('N'))"

try {
    New-Item -ItemType Directory -Path $work, $extract, $stage -Force | Out-Null
    Invoke-WebRequest -Uri $Url -OutFile $archive -UseBasicParsing -MaximumRedirection 1 -SslProtocol Tls12
    $actualSize = (Get-Item -LiteralPath $archive).Length
    if ($actualSize -ne $Size) {
        throw "WinSparkle archive size mismatch: expected $Size, got $actualSize."
    }
    $actualSha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualSha256 -cne $Sha256) {
        throw "WinSparkle archive SHA-256 mismatch: expected $Sha256, got $actualSha256."
    }

    Expand-Archive -LiteralPath $archive -DestinationPath $extract
    $root = Join-Path $extract "WinSparkle-$Version"
    $required = @{
        'x64\Release\WinSparkle.dll' = 'WinSparkle.dll'
        'x64\Release\WinSparkle.lib' = 'WinSparkle.lib'
        'include\winsparkle.h' = 'winsparkle.h'
        'bin\winsparkle-tool.exe' = 'winsparkle-tool.exe'
    }
    foreach ($entry in $required.GetEnumerator()) {
        $source = Join-Path $root $entry.Key
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw "Verified WinSparkle archive is missing $($entry.Key)."
        }
        Copy-Item -LiteralPath $source -Destination (Join-Path $stage $entry.Value)
    }

    if (Test-Path -LiteralPath $destDir) {
        Remove-Item -LiteralPath $destDir -Recurse -Force
    }
    Move-Item -LiteralPath $stage -Destination $destDir
    Write-Host "WinSparkle $Version verified and staged at $destDir" -ForegroundColor Green
} finally {
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
