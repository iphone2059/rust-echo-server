param(
    [Parameter(Mandatory)]
    [string] $ServerPath,
    [Parameter(Mandatory)]
    [string] $ClientPath
)

# Interoperability check against another toolchain's client (the C++ baseline by default).
# The server must echo byte-exactly over both protocols, across sessions and at the
# datagram-size boundary, and every run must stop cleanly.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ServerPath -PathType Leaf)) { throw "server executable not found: $ServerPath" }
if (-not (Test-Path -LiteralPath $ClientPath -PathType Leaf)) { throw "client executable not found: $ClientPath" }

$artifactRoot = Join-Path (Split-Path -Parent $PSScriptRoot) 'target/interop-artifacts'
$runName = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffffffZ') + '-' + [Guid]::NewGuid().ToString('N')
$runDirectory = Join-Path $artifactRoot $runName
$null = New-Item -Path $runDirectory -ItemType Directory -Force
$scenarioIndex = 0
Write-Host "Interop artifacts: $runDirectory"

function Get-FreeTcpPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { return ([System.Net.IPEndPoint] $listener.LocalEndpoint).Port } finally { $listener.Stop() }
}

function Get-FreeUdpPort {
    $socket = [System.Net.Sockets.UdpClient]::new(0, [System.Net.Sockets.AddressFamily]::InterNetwork)
    try { return ([System.Net.IPEndPoint] $socket.Client.LocalEndPoint).Port } finally { $socket.Dispose() }
}

function Invoke-Scenario {
    param(
        [string] $Label,
        [string] $Protocol,
        [int] $Port,
        [string[]] $ServerArguments,
        [string[]] $ClientArguments,
        [int] $ServerRunSeconds
    )
    $script:scenarioIndex++
    $scenarioName = '{0:D2}-{1}' -f $script:scenarioIndex, ($Label -replace '[^a-zA-Z0-9]+', '-')
    $scenarioDirectory = Join-Path $runDirectory $scenarioName
    $null = New-Item -Path $scenarioDirectory -ItemType Directory -Force
    $output = Join-Path $scenarioDirectory 'server.stdout.log'
    $errorFile = Join-Path $scenarioDirectory 'server.stderr.log'
    $clientOutputFile = Join-Path $scenarioDirectory 'client.stdout.log'
    $clientErrorFile = Join-Path $scenarioDirectory 'client.stderr.log'
    $arguments = @('/p', $Protocol, '/s', $Port) + $ServerArguments
    $clientCode = $null
    $scenarioError = $null
    $serverKilled = $false
    $server = Start-Process -FilePath $ServerPath -ArgumentList $arguments -RedirectStandardOutput $output -RedirectStandardError $errorFile -PassThru -NoNewWindow
    try {
        Start-Sleep -Milliseconds 400
        if ($server.HasExited) { throw "$Label server exited early with code $($server.ExitCode)" }
        & $ClientPath @ClientArguments 1> $clientOutputFile 2> $clientErrorFile
        $clientCode = $LASTEXITCODE
        $clientOutput = @(Get-Content -LiteralPath $clientOutputFile) + @(Get-Content -LiteralPath $clientErrorFile)
        if ($clientCode -ne 0) { throw "$Label client exited with $clientCode" }
        $summary = ($clientOutput | Where-Object { $_ -match 'corrupted=' } | Select-Object -Last 1)
        if ($summary -notmatch 'corrupted=0 lost=0') { throw "$Label client reported loss: $summary" }
        $server.WaitForExit(($ServerRunSeconds + 12) * 1000) | Out-Null
        if (-not $server.HasExited) { throw "$Label server did not stop cleanly" }
        if ($server.ExitCode -ne 0) {
            $text = (Get-Content -LiteralPath $errorFile -Raw) ?? ''
            throw "$Label server exited with $($server.ExitCode): $text"
        }
    } catch {
        $scenarioError = $_.ToString()
        throw
    } finally {
        $serverExitCode = if ($server.HasExited) { $server.ExitCode } else { $null }
        if (-not $server.HasExited) { $server.Kill($true); $serverKilled = $true }
        [ordered]@{
            label = $Label
            server_path = $ServerPath
            server_sha256 = (Get-FileHash -LiteralPath $ServerPath).Hash
            client_path = $ClientPath
            client_sha256 = (Get-FileHash -LiteralPath $ClientPath).Hash
            server_arguments = $arguments
            client_arguments = $ClientArguments
            server_run_seconds = $ServerRunSeconds
            client_exit_code = $clientCode
            server_exit_code_before_cleanup = $serverExitCode
            server_killed_for_cleanup = $serverKilled
            error = $scenarioError
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $scenarioDirectory 'scenario.json') -Encoding utf8
        $server.Dispose()
    }
}

$defaultPort = Get-FreeTcpPort
$defaultServer = @('/w', '5', '/q', '/threads', '2', '/cq', '1024', '/memory', '134217728', '/stats')
$defaultClient = @('127.0.0.1', '/p', 'tcp', '/r', $defaultPort, '/n', '5', '/t', '5')
Invoke-Scenario -Label 'TCP default payload' -Protocol 'tcp' -Port $defaultPort -ServerRunSeconds 5 -ServerArguments $defaultServer -ClientArguments $defaultClient
Write-Host 'PASS interop: TCP default payload'

$tcpPort = Get-FreeTcpPort
$multiServer = @('/w', '6', '/q', '/threads', '4', '/cq', '4096', '/memory', '268435456')
$multiClient = @('127.0.0.1', '/p', 'tcp', '/r', $tcpPort, '/n', '40', '/c', '16', '/t', '5', '/z', '4096')
Invoke-Scenario -Label 'TCP multi-session 4 KiB' -Protocol 'tcp' -Port $tcpPort -ServerRunSeconds 6 -ServerArguments $multiServer -ClientArguments $multiClient
Write-Host 'PASS interop: TCP multi-session 4 KiB echo'

$tcpBigPort = Get-FreeTcpPort
$bigServer = @('/w', '8', '/q', '/threads', '1', '/cq', '4096', '/memory', '268435456')
$bigClient = @('127.0.0.1', '/p', 'tcp', '/r', $tcpBigPort, '/n', '1', '/t', '20', '/z', '33554432')
Invoke-Scenario -Label 'TCP 32 MiB payload' -Protocol 'tcp' -Port $tcpBigPort -ServerRunSeconds 8 -ServerArguments $bigServer -ClientArguments $bigClient
Write-Host 'PASS interop: TCP 32 MiB payload echo'

$udpPort = Get-FreeUdpPort
$udpServer = @('/w', '5', '/q', '/k', '128', '/cq', '1024', '/memory', '67108864')
$udpClient = @('127.0.0.1', '/p', 'udp', '/r', $udpPort, '/n', '8', '/z', '1024', '/t', '5')
Invoke-Scenario -Label 'UDP 1 KiB datagrams' -Protocol 'udp' -Port $udpPort -ServerRunSeconds 5 -ServerArguments $udpServer -ClientArguments $udpClient
Write-Host 'PASS interop: UDP 1 KiB datagrams'

$udpBigPort = Get-FreeUdpPort
$udpBigServer = @('/w', '5', '/q', '/k', '64', '/cq', '1024', '/memory', '67108864', '/rio-buffer', '65507')
$udpBigClient = @('127.0.0.1', '/p', 'udp', '/r', $udpBigPort, '/n', '3', '/z', '65507', '/t', '5')
Invoke-Scenario -Label 'UDP 65507 byte datagrams' -Protocol 'udp' -Port $udpBigPort -ServerRunSeconds 5 -ServerArguments $udpBigServer -ClientArguments $udpBigClient
Write-Host 'PASS interop: UDP 65507 byte datagrams'

Write-Host 'PASS server interop with the reference client'
