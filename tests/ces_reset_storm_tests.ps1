param(
    [Parameter(Mandatory)][string] $ServerPath,
    [string] $Label = 'rust-echo-server',
    [int] $ResetConnections = 400,
    [int] $ServerSeconds = 8
)

# A client that connects and resets before AcceptEx completes must cost exactly one accept
# slot: the listener stays healthy and the next normal connection still echoes. The C++
# baseline and the Swift port both run this scenario (ces_reset_storm_tests.ps1); it pins
# the ERROR_NETNAME_DELETED path of the acceptor.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ServerPath -PathType Leaf)) {
    throw "server executable not found: $ServerPath"
}
if (-not ('CESResetStorm' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
public static class CESResetStorm {
    // Connect and reset immediately: the RST races the pending AcceptEx.
    public static long Run(int port, int total, int parallelism) {
        int issued = 0;
        long resets = 0;
        var endpoint = new IPEndPoint(IPAddress.Loopback, port);
        var tasks = new Task[parallelism];
        for (int i = 0; i < parallelism; i++) {
            tasks[i] = Task.Run(() => {
                while (true) {
                    int slot = Interlocked.Increment(ref issued);
                    if (slot > total) { return; }
                    var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    socket.LingerState = new LingerOption(true, 0);
                    try { socket.Connect(endpoint); Interlocked.Increment(ref resets); }
                    catch { }
                    finally { try { socket.Dispose(); } catch { } }
                }
            });
        }
        Task.WaitAll(tasks);
        return resets;
    }
    // One verified echo round trip.
    public static bool Echo(int port, byte[] payload) {
        try {
            using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)) {
                socket.Connect(new IPEndPoint(IPAddress.Loopback, port));
                socket.NoDelay = true;
                socket.Send(payload);
                var received = new byte[payload.Length];
                int offset = 0;
                while (offset < received.Length) {
                    int count = socket.Receive(received, offset, received.Length - offset, SocketFlags.None);
                    if (count == 0) { return false; }
                    offset += count;
                }
                for (int i = 0; i < payload.Length; i++) { if (received[i] != payload[i]) { return false; } }
                return true;
            }
        } catch { return false; }
    }
}
'@
}
function Get-FreeTcpPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { return ([System.Net.IPEndPoint] $listener.LocalEndpoint).Port } finally { $listener.Stop() }
}
function Wait-TcpReady {
    param([int]$Port, [int]$TimeoutMilliseconds = 10000)
    $deadline = [Environment]::TickCount64 + $TimeoutMilliseconds
    while ([Environment]::TickCount64 -lt $deadline) {
        $client = $null
        try { $client = [System.Net.Sockets.TcpClient]::new('127.0.0.1', $Port); return $true }
        catch { Start-Sleep -Milliseconds 50 } finally { if ($client) { $client.Dispose() } }
    }
    return $false
}
function Get-FinalLine {
    param([string]$Text)
    return (@($Text -split "\r?\n" | Where-Object { $_ -match '^final ' }) | Select-Object -Last 1)
}

$port = Get-FreeTcpPort
$outputPath = Join-Path $env:TEMP ("ces_reset_" + [Guid]::NewGuid().ToString('N') + ".out")
$errorPath = Join-Path $env:TEMP ("ces_reset_" + [Guid]::NewGuid().ToString('N') + ".err")
New-Item -ItemType File -Path $outputPath, $errorPath -Force | Out-Null
$serverArguments = @('/p', 'tcp', '/s', [string] $port, '/threads', '4', '/cq', '65536', '/memory', '1073741824', '/w', [string] $ServerSeconds, '/stats')
$server = Start-Process -FilePath $ServerPath -ArgumentList $serverArguments -PassThru -NoNewWindow -RedirectStandardOutput $outputPath -RedirectStandardError $errorPath
try {
    if (-not (Wait-TcpReady -Port $port)) { throw "$Label did not start listening" }
    $resets = [CESResetStorm]::Run($port, $ResetConnections, 32)
    if ($resets -lt $ResetConnections / 2) { throw "$Label only saw $resets of $ResetConnections resets" }
    if ($server.HasExited) { throw "$Label exited (code $($server.ExitCode)) after the pre-accept reset storm" }
    $payload = [byte[]]::new(1024)
    for ($index = 0; $index -lt $payload.Length; $index++) { $payload[$index] = [byte](($index * 7) % 251) }
    $echoed = $false
    foreach ($attempt in 1..20) {
        if ([CESResetStorm]::Echo($port, $payload)) { $echoed = $true; break }
        Start-Sleep -Milliseconds 200
    }
    if (-not $echoed) { throw "$Label stopped echoing after the pre-accept reset storm" }
    if (-not $server.WaitForExit(($ServerSeconds + 20) * 1000)) { throw "$Label did not stop within the run limit" }
    if ($server.ExitCode -ne 0) { throw "$Label exited with code $($server.ExitCode)" }
    $serverError = (Get-Content -LiteralPath $errorPath -Raw) ?? ''
    if ($serverError.Trim().Length -ne 0) { throw "$Label wrote to stderr: $($serverError.Trim())" }
    $final = Get-FinalLine -Text ((Get-Content -LiteralPath $outputPath -Raw) ?? '')
    if ($final -notmatch '^final protocol=tcp .* active=0') { throw "$Label terminal line missing: $final" }
    Write-Host "PASS $Label survives pre-accept resets: $resets reset connections, listener still echoing, $([regex]::Match($final, 'accepted=\d+').Value)"
} finally {
    if (-not $server.HasExited) { $server.Kill($true) }
    $server.Dispose()
    Remove-Item -LiteralPath $outputPath, $errorPath -Force -ErrorAction SilentlyContinue
}
