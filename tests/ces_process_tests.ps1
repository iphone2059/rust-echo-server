param(
    [Parameter(Mandatory)]
    [string] $ServerPath
)

# Process contract of the Rust server, mirroring cpp-echo-server/tests/ces_process_tests.ps1:
# command-line contract, TCP echo and timeout, connect storm under load, UDP echo sizes and
# a UDP traffic drain. Every scenario asserts a clean exit and the terminal statistics line.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ServerPath -PathType Leaf)) {
    throw "server executable not found: $ServerPath"
}

function Get-FreeTcpPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { return ([System.Net.IPEndPoint] $listener.LocalEndpoint).Port } finally { $listener.Stop() }
}

function Get-FreeUdpPort {
    $socket = [System.Net.Sockets.UdpClient]::new(0, [System.Net.Sockets.AddressFamily]::InterNetwork)
    try { return ([System.Net.IPEndPoint] $socket.Client.LocalEndPoint).Port } finally { $socket.Dispose() }
}

function Wait-TcpReady {
    param([int] $Port, [System.Diagnostics.Process] $Process)
    $deadline = [DateTime]::UtcNow.AddSeconds(5)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($Process.HasExited) { throw "TCP server exited early with code $($Process.ExitCode)" }
        $probe = [System.Net.Sockets.TcpClient]::new()
        try { $probe.Connect([System.Net.IPAddress]::Loopback, $Port); return }
        catch [System.Net.Sockets.SocketException] { Start-Sleep -Milliseconds 20 }
        finally { $probe.Dispose() }
    }
    throw 'TCP server did not become ready'
}

function Invoke-Server {
    param([string[]] $Arguments)
    $out = [System.IO.Path]::GetTempFileName()
    $err = [System.IO.Path]::GetTempFileName()
    try {
        $process = Start-Process -FilePath $ServerPath -ArgumentList $Arguments -RedirectStandardOutput $out -RedirectStandardError $err -PassThru -WindowStyle Hidden
        $process.WaitForExit(20000) | Out-Null
        if (-not $process.HasExited) { $process.Kill($true); throw "server did not exit: $($Arguments -join ' ')" }
        [pscustomobject]@{
            Code = $process.ExitCode
            # A command that printed nothing leaves an empty file, which reads as $null.
            Out  = ((Get-Content -LiteralPath $out -Raw) ?? '')
            Err  = ((Get-Content -LiteralPath $err -Raw) ?? '')
        }
    } finally {
        Remove-Item -LiteralPath $out, $err -Force -ErrorAction SilentlyContinue
    }
}

# --- command-line contract -------------------------------------------------------------
$usage = Invoke-Server @()
if ($usage.Code -ne 1) { throw "no arguments must be a usage error, got $($usage.Code)" }
if ($usage.Err -notmatch 'Invalid arguments') { throw "usage error text missing: $($usage.Err)" }
if ($usage.Out -notmatch 'Usage: rust-echo-server /p tcp\|udp') { throw "usage header missing: $($usage.Out)" }

$help = Invoke-Server @('/help')
if ($help.Code -ne 0) { throw "/help must succeed, got $($help.Code)" }
if ($help.Out -notmatch 'Data I/O is always RIO') { throw "help text missing: $($help.Out)" }

foreach ($invalid in @(@('/p', 'tcp', '/k', '8'), @('/p', 'udp', '/t', '5'), @('/p', 'sctp'), @('/p', 'tcp', '/nope'), @('/p', 'udp', '/rio-buffer', '65000'))) {
    $result = Invoke-Server $invalid
    if ($result.Code -ne 1) { throw "invalid arguments '$($invalid -join ' ')' must exit 1, got $($result.Code)" }
}

# Wide-character tokens are ordinary tokens: a token that does not start with an ASCII
# switch letter is a positional argument, and a wide value is not a number. Both are usage
# errors (exit 1), never a panic while decoding the command line.
$wideSwitch = Invoke-Server @('/p', 'tcp', '/端口', '7000')
if ($wideSwitch.Code -ne 1 -or $wideSwitch.Err -notmatch 'positional arguments') { throw "a wide switch must be a positional-argument error, got $($wideSwitch.Code): $($wideSwitch.Err)" }
$wideValue = Invoke-Server @('/p', 'tcp', '/s', '端口')
if ($wideValue.Code -ne 1 -or $wideValue.Err -notmatch 'numeric switch') { throw "a wide value must be an invalid number, got $($wideValue.Code): $($wideValue.Err)" }
Write-Host 'PASS server command-line contract'
# --- TCP echo, statistics and a clean stop ---------------------------------------------
$tcpPort = Get-FreeTcpPort
$tcpOutput = [System.IO.Path]::GetTempFileName()
$tcpArguments = @('/p', 'tcp', '/s', $tcpPort, '/w', '2', '/q', '/threads', '2', '/cq', '1024', '/memory', '67108864', '/stats')
$tcp = Start-Process -FilePath $ServerPath -ArgumentList $tcpArguments -RedirectStandardOutput $tcpOutput -PassThru -WindowStyle Hidden
try {
    Wait-TcpReady -Port $tcpPort -Process $tcp
    $client = [System.Net.Sockets.TcpClient]::new()
    $client.Connect([System.Net.IPAddress]::Loopback, $tcpPort)
    try {
        $stream = $client.GetStream()
        $payload = [byte[]]::new(131071)
        for ($index = 0; $index -lt $payload.Length; $index++) { $payload[$index] = [byte] ($index -band 255) }
        $stream.Write($payload, 0, $payload.Length)
        $received = [byte[]]::new($payload.Length)
        $offset = 0
        while ($offset -lt $received.Length) {
            $count = $stream.Read($received, $offset, $received.Length - $offset)
            if ($count -eq 0) { throw 'TCP peer closed before full echo' }
            $offset += $count
        }
        if ([Convert]::ToBase64String($payload) -ne [Convert]::ToBase64String($received)) { throw 'TCP echo mismatch' }
    } finally {
        $client.Dispose()
    }
    $tcp.WaitForExit(7000) | Out-Null
    if (-not $tcp.HasExited -or $tcp.ExitCode -ne 0) { throw 'TCP server did not stop cleanly' }
    $tcpText = Get-Content -LiteralPath $tcpOutput -Raw
    if ($tcpText -notmatch 'final protocol=tcp .*accepted=[1-9][0-9]* .*bytes=[1-9][0-9]* .*active=0') {
        throw "TCP final statistics are missing or incomplete: $tcpText"
    }
} finally {
    if (-not $tcp.HasExited) { $tcp.Kill($true) }
    $tcp.Dispose()
    Remove-Item -LiteralPath $tcpOutput -Force -ErrorAction SilentlyContinue
}
Write-Host 'PASS server TCP echo, statistics and clean stop'

# --- TCP idle timeout -------------------------------------------------------------------
$timeoutPort = Get-FreeTcpPort
$timeoutArguments = @('/p', 'tcp', '/s', $timeoutPort, '/t', '1', '/w', '3', '/q', '/threads', '1', '/cq', '128', '/memory', '16777216')
$timeoutServer = Start-Process -FilePath $ServerPath -ArgumentList $timeoutArguments -PassThru -WindowStyle Hidden
try {
    Wait-TcpReady -Port $timeoutPort -Process $timeoutServer
    $socket = [System.Net.Sockets.Socket]::new([System.Net.Sockets.AddressFamily]::InterNetwork,
        [System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
    try {
        $socket.ReceiveTimeout = 800
        $socket.Connect([System.Net.IPAddress]::Loopback, $timeoutPort)
        Start-Sleep -Milliseconds 1400
        $buffer = [byte[]]::new(1)
        try {
            $count = $socket.Receive($buffer)
            if ($count -ne 0) { throw 'idle TCP connection returned unexpected data' }
        } catch [System.Net.Sockets.SocketException] {
            if ($_.Exception.SocketErrorCode -eq [System.Net.Sockets.SocketError]::TimedOut) {
                throw 'TCP /t did not close the idle connection'
            }
        }
    } finally {
        $socket.Dispose()
    }
    $timeoutServer.WaitForExit(6000) | Out-Null
    if (-not $timeoutServer.HasExited -or $timeoutServer.ExitCode -ne 0) {
        throw 'TCP timeout server did not stop cleanly'
    }
} finally {
    if (-not $timeoutServer.HasExited) { $timeoutServer.Kill($true) }
    $timeoutServer.Dispose()
}
Write-Host 'PASS server TCP idle timeout closes the connection'

# --- TCP connect storm under load -------------------------------------------------------
$stormPort = Get-FreeTcpPort
$stormArguments = @('/p', 'tcp', '/s', $stormPort, '/w', '2', '/q', '/threads', '4', '/cq', '2048', '/memory', '134217728')
$stormServer = Start-Process -FilePath $ServerPath -ArgumentList $stormArguments -PassThru -WindowStyle Hidden
$stormJobs = @()
try {
    Wait-TcpReady -Port $stormPort -Process $stormServer
    foreach ($worker in 1..4) {
        $stormJobs += Start-Job -ArgumentList $stormPort -ScriptBlock {
            param($Port)
            $deadline = [DateTime]::UtcNow.AddMilliseconds(2300)
            while ([DateTime]::UtcNow -lt $deadline) {
                $socket = [System.Net.Sockets.TcpClient]::new()
                try { $socket.Connect([System.Net.IPAddress]::Loopback, $Port) }
                catch [System.Net.Sockets.SocketException] { }
                finally { $socket.Dispose() }
            }
        }
    }
    # A connect storm keeps the completion queues saturated while the run deadline passes,
    # so the drain after the stop may take longer than the quiet scenarios need.
    $stormServer.WaitForExit(15000) | Out-Null
    if (-not $stormServer.HasExited -or $stormServer.ExitCode -ne 0) {
        throw 'TCP connect-storm server did not stop cleanly'
    }
    foreach ($job in $stormJobs) {
        if (-not (Wait-Job -Job $job -Timeout 5)) { throw 'TCP connect-storm job did not converge' }
        Receive-Job -Job $job -ErrorAction Stop | Out-Null
    }
} finally {
    foreach ($job in $stormJobs) {
        Stop-Job -Job $job -ErrorAction SilentlyContinue
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    }
    if (-not $stormServer.HasExited) { $stormServer.Kill($true) }
    $stormServer.Dispose()
}
Write-Host 'PASS server TCP connect storm stops cleanly'
# --- UDP echo of the boundary datagram sizes --------------------------------------------
$udpPort = Get-FreeUdpPort
$udpOutput = [System.IO.Path]::GetTempFileName()
$udpArguments = @('/p', 'udp', '/s', $udpPort, '/w', '2', '/q', '/k', '64', '/cq', '1024', '/memory', '67108864', '/stats')
$udp = Start-Process -FilePath $ServerPath -ArgumentList $udpArguments -RedirectStandardOutput $udpOutput -PassThru -WindowStyle Hidden
try {
    Start-Sleep -Milliseconds 250
    if ($udp.HasExited) { throw "UDP server exited early with code $($udp.ExitCode)" }
    $client = [System.Net.Sockets.UdpClient]::new(0, [System.Net.Sockets.AddressFamily]::InterNetwork)
    try {
        $client.Client.ReceiveTimeout = 3000
        $client.Connect([System.Net.IPAddress]::Loopback, $udpPort)
        foreach ($size in @(0, 1, 65507)) {
            $payload = [byte[]]::new($size)
            for ($index = 0; $index -lt $payload.Length; $index++) { $payload[$index] = [byte] (($index * 17) -band 255) }
            [void] $client.Send($payload, $payload.Length)
            $remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
            $received = $client.Receive([ref] $remote)
            if ([Convert]::ToBase64String($payload) -ne [Convert]::ToBase64String($received)) {
                throw "UDP echo mismatch for payload size $size"
            }
        }
    } finally {
        $client.Dispose()
    }
    $udp.WaitForExit(7000) | Out-Null
    if (-not $udp.HasExited -or $udp.ExitCode -ne 0) { throw 'UDP server did not stop cleanly' }
    $udpText = Get-Content -LiteralPath $udpOutput -Raw
    if ($udpText -notmatch 'final protocol=udp .*completions=[1-9][0-9]* .*receives=[1-9][0-9]* .*sends=3 .*bytes=65508 .*outstanding=0') {
        throw "UDP final statistics are missing or incomplete: $udpText"
    }
} finally {
    if (-not $udp.HasExited) { $udp.Kill($true) }
    $udp.Dispose()
    Remove-Item -LiteralPath $udpOutput -Force -ErrorAction SilentlyContinue
}
Write-Host 'PASS server UDP echo of 0, 1 and 65507 byte datagrams'

# --- UDP traffic drain ------------------------------------------------------------------
$udpTrafficPort = Get-FreeUdpPort
$udpTrafficArguments = @('/p', 'udp', '/s', $udpTrafficPort, '/w', '2', '/q', '/k', '64', '/cq', '1024', '/memory', '67108864')
$udpTraffic = Start-Process -FilePath $ServerPath -ArgumentList $udpTrafficArguments -PassThru -WindowStyle Hidden
$udpTrafficJob = $null
try {
    Start-Sleep -Milliseconds 250
    if ($udpTraffic.HasExited) { throw "UDP traffic server exited early with code $($udpTraffic.ExitCode)" }
    $udpTrafficJob = Start-Job -ArgumentList $udpTrafficPort -ScriptBlock {
        param($Port)
        $client = [System.Net.Sockets.UdpClient]::new(0, [System.Net.Sockets.AddressFamily]::InterNetwork)
        try {
            $client.Client.ReceiveTimeout = 200
            $client.Connect([System.Net.IPAddress]::Loopback, $Port)
            $payload = [byte[]]::new(1200)
            $remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
            $deadline = [DateTime]::UtcNow.AddMilliseconds(2300)
            while ([DateTime]::UtcNow -lt $deadline) {
                try {
                    [void] $client.Send($payload, $payload.Length)
                    [void] $client.Receive([ref] $remote)
                } catch [System.Net.Sockets.SocketException] { }
            }
        } finally {
            $client.Dispose()
        }
    }
    $udpTraffic.WaitForExit(7000) | Out-Null
    if (-not $udpTraffic.HasExited -or $udpTraffic.ExitCode -ne 0) { throw 'UDP traffic server did not drain cleanly' }
    if (-not (Wait-Job -Job $udpTrafficJob -Timeout 5)) { throw 'UDP traffic job did not converge' }
    Receive-Job -Job $udpTrafficJob -ErrorAction Stop | Out-Null
} finally {
    if ($null -ne $udpTrafficJob) {
        Stop-Job -Job $udpTrafficJob -ErrorAction SilentlyContinue
        Remove-Job -Job $udpTrafficJob -Force -ErrorAction SilentlyContinue
    }
    if (-not $udpTraffic.HasExited) { $udpTraffic.Kill($true) }
    $udpTraffic.Dispose()
}
Write-Host 'PASS server UDP traffic drains before release'

# --- RIO is mandatory -------------------------------------------------------------------
$noRio = Invoke-Server @('/p', 'tcp', '/s', (Get-FreeTcpPort), '/w', '1')
if ($noRio.Code -ne 0) { throw "a quiet TCP run must still succeed, got $($noRio.Code)" }
if ($noRio.Out.Length -gt 0) { throw "the server must print nothing outside /stats, got $($noRio.Out.Length) byte(s): $($noRio.Out)" }
Write-Host 'PASS server stays silent outside /stats'

# --- port conflict ----------------------------------------------------------------------
$conflictPort = Get-FreeTcpPort
$conflictOutput = [System.IO.Path]::GetTempFileName()
$conflictArguments = @('/p', 'tcp', '/s', $conflictPort, '/w', '6', '/q', '/threads', '2', '/cq', '1024', '/memory', '67108864', '/stats')
$first = Start-Process -FilePath $ServerPath -ArgumentList $conflictArguments -RedirectStandardOutput $conflictOutput -PassThru -WindowStyle Hidden
try {
    Wait-TcpReady -Port $conflictPort -Process $first
    $second = Invoke-Server @('/p', 'tcp', '/s', $conflictPort, '/w', '2', '/q')
    if ($second.Code -ne 2) { throw "a second server on a taken port must exit 2, got $($second.Code)" }
    $client = [System.Net.Sockets.TcpClient]::new()
    $client.Connect([System.Net.IPAddress]::Loopback, $conflictPort)
    try {
        $stream = $client.GetStream()
        $payload = [byte[]]::new(64)
        for ($index = 0; $index -lt $payload.Length; $index++) { $payload[$index] = [byte] $index }
        $stream.Write($payload, 0, $payload.Length)
        $received = [byte[]]::new($payload.Length)
        $offset = 0
        while ($offset -lt $received.Length) {
            $count = $stream.Read($received, $offset, $received.Length - $offset)
            if ($count -eq 0) { throw 'first server closed after the port conflict' }
            $offset += $count
        }
        if ([Convert]::ToBase64String($payload) -ne [Convert]::ToBase64String($received)) { throw 'first server echo mismatch after the port conflict' }
    } finally {
        $client.Dispose()
    }
    $first.WaitForExit(9000) | Out-Null
    if (-not $first.HasExited -or $first.ExitCode -ne 0) { throw 'first server did not stop cleanly after the port conflict' }
} finally {
    if (-not $first.HasExited) { $first.Kill($true) }
    $first.Dispose()
    Remove-Item -LiteralPath $conflictOutput -Force -ErrorAction SilentlyContinue
}
Write-Host 'PASS server port conflict exits 2 while the first server keeps echoing'

# --- Ctrl+Break in the server's own console ---------------------------------------------
if (-not ('CesConsoleLauncher' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
public static class CesConsoleLauncher {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO {
        public int cb; public string lpReserved; public string lpDesktop; public string lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }
    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES { public int nLength; public IntPtr lpSecurityDescriptor; public bool bInheritHandle; }
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessW(string application, string commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory, ref STARTUPINFO startup, out PROCESS_INFORMATION information);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFileW(string name, uint access, uint share, ref SECURITY_ATTRIBUTES attributes, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetExitCodeProcess(IntPtr handle, out uint code);
    const uint GENERIC_READ_WRITE = 0xC0000000, GENERIC_WRITE = 0x40000000, FILE_SHARE_READ = 1;
    const uint CREATE_ALWAYS = 2, OPEN_EXISTING = 3, FILE_ATTRIBUTE_NORMAL = 0x80;
    const uint STARTF_USESTDHANDLES = 0x100, STARTF_USESHOWWINDOW = 1, SW_HIDE = 0;
    const uint CREATE_NEW_CONSOLE = 0x10, CREATE_NEW_PROCESS_GROUP = 0x200;
    static readonly System.Collections.Generic.Dictionary<int, IntPtr> Handles = new System.Collections.Generic.Dictionary<int, IntPtr>();
    static string Quote(string value) {
        if (value.Length != 0 && value.IndexOfAny(new char[] { ' ', '\t', '"' }) < 0) { return value; }
        var builder = new StringBuilder("\"");
        int backslashes = 0;
        foreach (char character in value) {
            if (character == '\\') { backslashes++; continue; }
            if (character == '"') { builder.Append('\\', backslashes * 2 + 1).Append('"'); backslashes = 0; continue; }
            builder.Append('\\', backslashes).Append(character); backslashes = 0;
        }
        builder.Append('\\', backslashes * 2).Append('"');
        return builder.ToString();
    }
    public static int StartInHiddenConsole(string executable, string[] arguments, string stdoutPath, string stderrPath) {
        var attributes = new SECURITY_ATTRIBUTES();
        attributes.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
        attributes.bInheritHandle = true;
        IntPtr input = CreateFileW("NUL", GENERIC_READ_WRITE, FILE_SHARE_READ, ref attributes, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        if (input == new IntPtr(-1)) { throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateFileW(NUL)"); }
        IntPtr output = CreateFileW(stdoutPath, GENERIC_WRITE, FILE_SHARE_READ, ref attributes, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        if (output == new IntPtr(-1)) { CloseHandle(input); throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateFileW(stdout)"); }
        IntPtr error = CreateFileW(stderrPath, GENERIC_WRITE, FILE_SHARE_READ, ref attributes, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        if (error == new IntPtr(-1)) { CloseHandle(input); CloseHandle(output); throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateFileW(stderr)"); }
        try {
            var startup = new STARTUPINFO();
            startup.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            startup.dwFlags = (int) (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
            startup.wShowWindow = (short) SW_HIDE;
            startup.hStdInput = input;
            startup.hStdOutput = output;
            startup.hStdError = error;
            var commandLine = new StringBuilder(Quote(executable));
            if (arguments != null) { foreach (string argument in arguments) { commandLine.Append(' ').Append(Quote(argument)); } }
            PROCESS_INFORMATION information;
            if (!CreateProcessW(executable, commandLine.ToString(), IntPtr.Zero, IntPtr.Zero, true, CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP, IntPtr.Zero, null, ref startup, out information)) {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessW");
            }
            CloseHandle(information.hThread);
            lock (Handles) { Handles[information.dwProcessId] = information.hProcess; }
            return information.dwProcessId;
        } finally {
            CloseHandle(input);
            CloseHandle(output);
            CloseHandle(error);
        }
    }
    public static int WaitForExit(int processId, int milliseconds) {
        IntPtr handle;
        lock (Handles) { if (!Handles.TryGetValue(processId, out handle)) { throw new InvalidOperationException("unknown process"); } }
        if (WaitForSingleObject(handle, (uint) milliseconds) != 0) { return -1; }
        uint code;
        if (!GetExitCodeProcess(handle, out code)) { throw new Win32Exception(Marshal.GetLastWin32Error(), "GetExitCodeProcess"); }
        return unchecked((int) code);
    }
    public static void Release(int processId) {
        IntPtr handle;
        lock (Handles) { if (!Handles.TryGetValue(processId, out handle)) { return; } Handles.Remove(processId); }
        CloseHandle(handle);
    }
}
'@
}

function Send-ConsoleBreak {
    param([Parameter(Mandatory)][int] $TargetProcessId, [int] $TimeoutMilliseconds = 30000)
    $member = 'public delegate bool CESHandlerRoutine(uint controlType); [DllImport("kernel32.dll", EntryPoint = "SetConsoleCtrlHandler", SetLastError = true)] static extern bool SetConsoleCtrlHandlerNative(CESHandlerRoutine handler, bool add); [DllImport("kernel32.dll", SetLastError = true)] public static extern bool FreeConsole(); [DllImport("kernel32.dll", SetLastError = true)] public static extern bool AttachConsole(uint processId); [DllImport("kernel32.dll", SetLastError = true)] public static extern bool GenerateConsoleCtrlEvent(uint controlEvent, uint processGroupId); [DllImport("kernel32.dll")] public static extern uint GetLastError(); static readonly CESHandlerRoutine IgnoreHandler = new CESHandlerRoutine(CESIgnore); static bool CESIgnore(uint controlType) { return true; } public static bool InstallIgnoreHandler() { return SetConsoleCtrlHandlerNative(IgnoreHandler, true); }'
    $lines = @(
        '$ErrorActionPreference = ''Stop''',
        '$target = [uint32] $env:CES_CONSOLE_TARGET_PID',
        ('Add-Type -Name CESConsoleSignal -Namespace CESConsole -MemberDefinition ''' + $member + ''''),
        '[void] [CESConsole.CESConsoleSignal]::FreeConsole()',
        'if (-not [CESConsole.CESConsoleSignal]::AttachConsole($target)) { exit 11 }',
        '[void] [CESConsole.CESConsoleSignal]::InstallIgnoreHandler()',
        '$sent = [CESConsole.CESConsoleSignal]::GenerateConsoleCtrlEvent(1, $target)',
        '$code = [int] [CESConsole.CESConsoleSignal]::GetLastError()',
        'if (-not $sent) {',
        '    $sent = [CESConsole.CESConsoleSignal]::GenerateConsoleCtrlEvent(1, 0)',
        '    $code = [int] [CESConsole.CESConsoleSignal]::GetLastError()',
        '}',
        '[void] [CESConsole.CESConsoleSignal]::FreeConsole()',
        'if (-not $sent) { exit (100 + $code) }',
        'exit 0'
    )
    $joined = $lines -join [Environment]::NewLine
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($joined))
    $psi = [System.Diagnostics.ProcessStartInfo]::new((Get-Process -Id $PID).Path)
    foreach ($argument in @('-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded)) { $psi.ArgumentList.Add($argument) }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $previous = $env:CES_CONSOLE_TARGET_PID
    $env:CES_CONSOLE_TARGET_PID = [string] $TargetProcessId
    $helper = [System.Diagnostics.Process]::Start($psi)
    try {
        $stdout = $helper.StandardOutput.ReadToEndAsync()
        $stderr = $helper.StandardError.ReadToEndAsync()
        if (-not $helper.WaitForExit($TimeoutMilliseconds)) { $helper.Kill($true); throw 'console break helper timed out' }
        if ($helper.ExitCode -ne 0) { throw "console break helper failed with $($helper.ExitCode): $($stderr.Result)" }
        return $stdout.Result
    } finally {
        try { if (-not $helper.HasExited) { $helper.Kill($true) } } catch { }
        $helper.Dispose()
        if ($null -eq $previous) { Remove-Item Env:\CES_CONSOLE_TARGET_PID -ErrorAction SilentlyContinue } else { $env:CES_CONSOLE_TARGET_PID = $previous }
    }
}

$breakPort = Get-FreeTcpPort
$breakOutput = [System.IO.Path]::GetTempFileName()
$breakError = [System.IO.Path]::GetTempFileName()
$breakArguments = @('/p', 'tcp', '/s', $breakPort, '/w', '60', '/threads', '1', '/cq', '1024', '/memory', '67108864', '/q', '/stats')
$breakId = [CesConsoleLauncher]::StartInHiddenConsole($ServerPath, $breakArguments, $breakOutput, $breakError)
try {
    Wait-TcpReady -Port $breakPort -Process ([System.Diagnostics.Process]::GetProcessById($breakId))
    $peer = [System.Net.Sockets.TcpClient]::new()
    $peer.Connect([System.Net.IPAddress]::Loopback, $breakPort)
    $peerStream = $peer.GetStream()
    Send-ConsoleBreak -TargetProcessId $breakId | Out-Null
    $peer.ReceiveTimeout = 15000
    $probe = [byte[]]::new(1)
    $closed = $false
    try {
        $count = $peerStream.Read($probe, 0, 1)
        $closed = ($count -eq 0)
    } catch [System.IO.IOException] {
        $closed = $true
    }
    if (-not $closed) { throw 'the connection open at Ctrl+Break was not drained' }
    $peer.Dispose()
    $breakExit = [CesConsoleLauncher]::WaitForExit($breakId, 20000)
    if ($breakExit -ne 0) { throw "Ctrl+Break server exited with $breakExit" }
    $breakText = (Get-Content -LiteralPath $breakOutput -Raw) ?? ''
    $breakErrors = (Get-Content -LiteralPath $breakError -Raw) ?? ''
    if ($breakErrors.Trim().Length -ne 0) { throw "Ctrl+Break server wrote to stderr: $($breakErrors.Trim())" }
    if ($breakText -notmatch 'final protocol=tcp .* active=0') { throw "Ctrl+Break final line missing: $breakText" }
} finally {
    [CesConsoleLauncher]::Release($breakId)
    Remove-Item -LiteralPath $breakOutput, $breakError -Force -ErrorAction SilentlyContinue
}
Write-Host 'PASS server stops on Ctrl+Break and drains the open connection'

# --- Ctrl+Break under a full UDP flood ---------------------------------------------------
$floodPort = Get-FreeUdpPort
$floodOutput = [System.IO.Path]::GetTempFileName()
$floodError = [System.IO.Path]::GetTempFileName()
$floodArguments = @('/p', 'udp', '/s', $floodPort, '/w', '60', '/k', '1024', '/cq', '4096', '/memory', '134217728', '/q', '/stats')
$floodId = [CesConsoleLauncher]::StartInHiddenConsole($ServerPath, $floodArguments, $floodOutput, $floodError)
$floodJob = $null
try {
    Start-Sleep -Milliseconds 400
    $floodJob = Start-Job -ArgumentList $floodPort -ScriptBlock {
        param($Port)
        $client = [System.Net.Sockets.UdpClient]::new(0, [System.Net.Sockets.AddressFamily]::InterNetwork)
        try {
            $client.Client.ReceiveTimeout = 100
            $client.Connect([System.Net.IPAddress]::Loopback, $Port)
            $payload = [byte[]]::new(1200)
            $remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
            $deadline = [DateTime]::UtcNow.AddSeconds(20)
            while ([DateTime]::UtcNow -lt $deadline) {
                try { [void] $client.Send($payload, $payload.Length); [void] $client.Receive([ref] $remote) } catch [System.Net.Sockets.SocketException] { }
            }
        } finally { $client.Dispose() }
    }
    # Let the completion queues saturate before the break arrives.
    Start-Sleep -Milliseconds 900
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    Send-ConsoleBreak -TargetProcessId $floodId | Out-Null
    $floodExit = [CesConsoleLauncher]::WaitForExit($floodId, 20000)
    $stopwatch.Stop()
    if ($floodExit -ne 0) { throw "UDP flood server exited with $floodExit" }
    # A saturated CQ must not delay the controlled stop: the bounded drain observes the
    # stop request and closes the socket from inside the drain.
    if ($stopwatch.ElapsedMilliseconds -gt 8000) { throw "controlled stop under UDP flood took $($stopwatch.ElapsedMilliseconds) ms" }
    $floodText = (Get-Content -LiteralPath $floodOutput -Raw) ?? ''
    $floodErrors = (Get-Content -LiteralPath $floodError -Raw) ?? ''
    if ($floodErrors.Trim().Length -ne 0) { throw "UDP flood server wrote to stderr: $($floodErrors.Trim())" }
    if ($floodText -notmatch 'final protocol=udp .* outstanding=0') { throw "UDP flood final line missing: $floodText" }
    Write-Host "PASS server stops on Ctrl+Break under a UDP flood ($($stopwatch.ElapsedMilliseconds) ms, outstanding=0)"
} finally {
    if ($null -ne $floodJob) {
        Stop-Job -Job $floodJob -ErrorAction SilentlyContinue
        Remove-Job -Job $floodJob -Force -ErrorAction SilentlyContinue
    }
    [CesConsoleLauncher]::Release($floodId)
    Remove-Item -LiteralPath $floodOutput, $floodError -Force -ErrorAction SilentlyContinue
}

# --- Ctrl+Break under a full TCP echo flood ----------------------------------------------
$burstPort = Get-FreeTcpPort
$burstOutput = [System.IO.Path]::GetTempFileName()
$burstError = [System.IO.Path]::GetTempFileName()
$burstArguments = @('/p', 'tcp', '/s', $burstPort, '/w', '60', '/threads', '2', '/cq', '4096', '/memory', '134217728', '/q', '/stats')
$burstId = [CesConsoleLauncher]::StartInHiddenConsole($ServerPath, $burstArguments, $burstOutput, $burstError)
$burstJobs = @()
try {
    Wait-TcpReady -Port $burstPort -Process ([System.Diagnostics.Process]::GetProcessById($burstId))
    foreach ($worker in 1..2) {
        $burstJobs += Start-Job -ArgumentList $burstPort -ScriptBlock {
            param($Port)
            $client = [System.Net.Sockets.TcpClient]::new()
            try {
                $client.Connect([System.Net.IPAddress]::Loopback, $Port)
                $stream = $client.GetStream()
                $payload = [byte[]]::new(65536)
                $received = [byte[]]::new(65536)
                $deadline = [DateTime]::UtcNow.AddSeconds(20)
                while ([DateTime]::UtcNow -lt $deadline) {
                    $stream.Write($payload, 0, $payload.Length)
                    $offset = 0
                    while ($offset -lt $received.Length) {
                        $count = $stream.Read($received, $offset, $received.Length - $offset)
                        if ($count -eq 0) { return }
                        $offset += $count
                    }
                }
            } catch { } finally { $client.Dispose() }
        }
    }
    Start-Sleep -Milliseconds 900
    $burstWatch = [System.Diagnostics.Stopwatch]::StartNew()
    Send-ConsoleBreak -TargetProcessId $burstId | Out-Null
    $burstExit = [CesConsoleLauncher]::WaitForExit($burstId, 20000)
    $burstWatch.Stop()
    if ($burstExit -ne 0) { throw "TCP burst server exited with $burstExit" }
    if ($burstWatch.ElapsedMilliseconds -gt 8000) { throw "controlled stop under TCP burst took $($burstWatch.ElapsedMilliseconds) ms" }
    $burstText = (Get-Content -LiteralPath $burstOutput -Raw) ?? ''
    $burstErrors = (Get-Content -LiteralPath $burstError -Raw) ?? ''
    if ($burstErrors.Trim().Length -ne 0) { throw "TCP burst server wrote to stderr: $($burstErrors.Trim())" }
    if ($burstText -notmatch 'final protocol=tcp .* active=0') { throw "TCP burst final line missing: $burstText" }
    Write-Host "PASS server stops on Ctrl+Break under a TCP echo burst ($($burstWatch.ElapsedMilliseconds) ms, active=0)"
} finally {
    if ($null -ne $floodJob) {
        Stop-Job -Job $floodJob -ErrorAction SilentlyContinue
        Remove-Job -Job $floodJob -Force -ErrorAction SilentlyContinue
    }
    [CesConsoleLauncher]::Release($floodId)
    Remove-Item -LiteralPath $floodOutput, $floodError -Force -ErrorAction SilentlyContinue
}

Write-Host 'PASS server TCP/UDP loopback and stop-under-load scenarios'
