# PowerShell one-line installer for dep-tracker on Windows
# Usage: irm https://raw.githubusercontent.com/nyumuharon/dependency-tracker/main/scripts/install.ps1 | iex

$ErrorActionPreference = "Stop"

$repo = "nyumuharon/dependency-tracker"
$installDir = Join-Path $HOME ".dep-tracker\bin"
$exePath = Join-Path $installDir "dep-tracker.exe"

# 1. Determine architecture
$arch = if ([System.Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") {
    $arch = "arm64"
}

# 2. Get latest release version tag
Write-Host "Fetching latest release information for dep-tracker..." -ForegroundColor Cyan
$releaseUrl = "https://api.github.com/repos/$repo/releases/latest"
try {
    $release = Invoke-RestMethod -Uri $releaseUrl -Headers @{ "User-Agent" = "dep-tracker-installer" }
    $tag = $release.tag_name
} catch {
    $tag = "v1.0.2"
}

# 3. Create install directory
if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
}

# 4. Download binary
$downloadUrl = "https://github.com/$repo/releases/download/$tag/dep-tracker-windows-amd64.exe"
Write-Host "Downloading dep-tracker ($tag)..." -ForegroundColor Cyan

$tempFile = Join-Path $env:TEMP "dep-tracker-download-$((Get-Random)).exe"
try {
    # Use curl.exe if available for speed and reliability, otherwise fallback to WebClient
    if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
        & curl.exe -L --progress-bar -o $tempFile $downloadUrl
    } else {
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($downloadUrl, $tempFile)
    }

    Move-Item -Path $tempFile -Destination $exePath -Force
} catch {
    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
    Write-Error "Failed to download dep-tracker: $_"
    return
}

# 5. Ensure install directory is in User PATH
$userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -split ";" -notcontains $installDir -and $userPath -notlike "*$installDir*") {
    Write-Host "Adding $installDir to User PATH..." -ForegroundColor Cyan
    $newPath = "$userPath;$installDir"
    [System.Environment]::SetEnvironmentVariable("Path", $newPath, "User")
}

# 6. Update current PowerShell session PATH so it works immediately
if ($env:Path -split ";" -notcontains $installDir) {
    $env:Path = "$installDir;$env:Path"
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " dep-tracker ($tag) installed successfully!" -ForegroundColor Green
Write-Host " Location: $exePath" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Try running:" -ForegroundColor Yellow
Write-Host "  dep-tracker --help" -ForegroundColor White
Write-Host "  dep-tracker scan ." -ForegroundColor White
Write-Host ""
