# Offline tests run on native Windows. All downloads are mocked and the user
# and process PATH are restored when testing finishes.
$ErrorActionPreference = 'Stop'
$installerPath = Join-Path $PSScriptRoot 'install.ps1'
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('dep-tracker-test-' + [guid]::NewGuid())
$originalProcessPath = $env:Path
$originalUserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$originalInstallDir = $env:DEP_TRACKER_INSTALL_DIR
$originalTestMode = $env:DEP_TRACKER_TEST_MODE
New-Item -ItemType Directory -Path $testRoot | Out-Null
$fixture = Join-Path $testRoot 'fixture.exe'
[IO.File]::WriteAllText($fixture, 'verified binary')
$fixtureHash = (Get-FileHash -Path $fixture -Algorithm SHA256).Hash

function Invoke-RestMethod {
    param($Uri, $Headers)
    if ($env:DEP_TRACKER_TEST_MODE -eq 'api-failed') { throw 'Simulated API failure' }
    return [pscustomobject]@{ tag_name = 'v1.0.7' }
}

function Invoke-WebRequest {
    param($Uri, $OutFile, [switch]$UseBasicParsing)
    if ($Uri -like '*/SHA256SUMS.txt') {
        if ($env:DEP_TRACKER_TEST_MODE -eq 'missing-checksum') { return [pscustomobject]@{ Content = '' } }
        $text = "$fixtureHash  dep-tracker-windows-amd64.exe`n"
        if ($env:DEP_TRACKER_TEST_MODE -eq 'valid-bytes') {
            return [pscustomobject]@{ Content = [System.Text.Encoding]::UTF8.GetBytes($text) }
        }
        if ($env:DEP_TRACKER_TEST_MODE -eq 'duplicate-checksum') { $text += $text }
        return [pscustomobject]@{ Content = $text }
    }
    if ($env:DEP_TRACKER_TEST_MODE -eq 'download-failed') { throw 'Simulated download failure' }
    if ($env:DEP_TRACKER_TEST_MODE -eq 'tampered') {
        [IO.File]::WriteAllText($OutFile, 'tampered binary')
    } else {
        Copy-Item -Path $fixture -Destination $OutFile
    }
}

try {
    foreach ($mode in @('valid', 'valid-bytes', 'tampered', 'missing-checksum', 'duplicate-checksum', 'download-failed', 'api-failed')) {
        $env:DEP_TRACKER_TEST_MODE = $mode
        $env:DEP_TRACKER_INSTALL_DIR = Join-Path $testRoot $mode
        New-Item -ItemType Directory -Path $env:DEP_TRACKER_INSTALL_DIR | Out-Null
        $installed = Join-Path $env:DEP_TRACKER_INSTALL_DIR 'dep-tracker.exe'
        [IO.File]::WriteAllText($installed, 'existing binary')
        $succeeded = $false
        try {
            & $installerPath
            $succeeded = $true
        } catch {
            if ($mode -in @('valid', 'valid-bytes')) { throw }
        }
        if ($succeeded -ne ($mode -in @('valid', 'valid-bytes'))) { throw "Unexpected outcome: $mode" }
        if ($mode -in @('valid', 'valid-bytes')) {
            if ((Get-FileHash $installed -Algorithm SHA256).Hash -ne $fixtureHash) { throw 'Installed binary differs from the verified download' }
            if (($env:Path -split ';') -notcontains $env:DEP_TRACKER_INSTALL_DIR) { throw 'Process PATH was not updated' }
            $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
            if (($userPath -split ';') -notcontains $env:DEP_TRACKER_INSTALL_DIR) { throw 'User PATH was not updated' }
        } elseif ([IO.File]::ReadAllText($installed) -ne 'existing binary') {
            throw "Existing executable changed after failure: $mode"
        }
        Write-Host "Installer test passed: $mode"
    }
} finally {
    $env:Path = $originalProcessPath
    [Environment]::SetEnvironmentVariable('Path', $originalUserPath, 'User')
    $env:DEP_TRACKER_INSTALL_DIR = $originalInstallDir
    $env:DEP_TRACKER_TEST_MODE = $originalTestMode
    Remove-Item -Recurse -Force $testRoot
}
