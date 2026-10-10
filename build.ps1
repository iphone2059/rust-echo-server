# Builds and verifies rust-echo-server with the selected Cargo profile.
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string] $Configuration = 'Debug',
    [string] $InteropClientPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$projectRoot = $PSScriptRoot
$lockPath = Join-Path $projectRoot 'Cargo.lock'
Push-Location $projectRoot
try {
    if (Test-Path -LiteralPath $lockPath) { Remove-Item -LiteralPath $lockPath -Force }
    Write-Host '== cargo update'
    & cargo update
    if ($LASTEXITCODE -ne 0) { throw 'cargo update failed.' }

    Write-Host '== server source policy'
    & pwsh -NoProfile -File (Join-Path $projectRoot 'tests/ces_source_policy.ps1') -ProjectRoot $projectRoot
    if ($LASTEXITCODE -ne 0) { throw 'server source policy failed.' }

    $profileArguments = @()
    if ($Configuration -eq 'Release') { $profileArguments += '--release' }
    Write-Host "== cargo build $($profileArguments -join ' ')"
    & cargo build @profileArguments
    if ($LASTEXITCODE -ne 0) { throw 'cargo build failed.' }

    Write-Host "== cargo test $($profileArguments -join ' ')"
    & cargo test @profileArguments
    if ($LASTEXITCODE -ne 0) { throw 'cargo test failed.' }

    $serverPath = Join-Path $projectRoot ("target/" + $Configuration.ToLowerInvariant() + '/rust-echo-server.exe')
    Write-Host '== server process contract'
    & pwsh -NoProfile -File (Join-Path $projectRoot 'tests/ces_process_tests.ps1') -ServerPath $serverPath
    if ($LASTEXITCODE -ne 0) { throw 'server process verification failed.' }

    Write-Host '== server reset storm'
    & pwsh -NoProfile -File (Join-Path $projectRoot 'tests/ces_reset_storm_tests.ps1') -ServerPath $serverPath -Label "rust-echo-server $Configuration"
    if ($LASTEXITCODE -ne 0) { throw 'server reset storm failed.' }

    if ($InteropClientPath) {
        Write-Host '== server interop with the reference client'
        & pwsh -NoProfile -File (Join-Path $projectRoot 'tests/ces_interop_tests.ps1') -ServerPath $serverPath -ClientPath $InteropClientPath
        if ($LASTEXITCODE -ne 0) { throw 'server interop verification failed.' }
    } else {
        Write-Host '== interop skipped (pass -InteropClientPath to run it)'
    }
} finally {
    if (Test-Path -LiteralPath $lockPath) { Remove-Item -LiteralPath $lockPath -Force }
    Pop-Location
}

if ($InteropClientPath) {
    Write-Host "PASS rust-echo-server $Configuration build, source policy, tests, reset storm and interop"
} else {
    Write-Host "PASS rust-echo-server $Configuration build, source policy, tests and reset storm"
}
