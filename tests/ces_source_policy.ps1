param(
    [Parameter(Mandatory)]
    [string] $ProjectRoot
)

# Source policy of the Rust server, mirroring cpp-echo-server/tests/ces_source_policy.ps1:
# the data path is RIO only, the library never panics on a failure, and no project borrows
# from a sibling port. Test code (#[cfg(test)] and everything after it) is exempt from the
# panic rule, because tests are allowed to assert.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path -LiteralPath $ProjectRoot).Path
$sources = @(Get-ChildItem -LiteralPath (Join-Path $root 'src') -File -Recurse | Where-Object { $_.Extension -eq '.rs' })
$failures = [System.Collections.Generic.List[string]]::new()

function Test-RustPattern {
    param(
        [string] $Pattern,
        [string] $Label,
        [System.IO.FileInfo[]] $Files,
        [switch] $SkipTests
    )
    foreach ($file in $Files) {
        $text = Get-Content -LiteralPath $file.FullName -Raw
        if ($null -eq $text) { continue }
        if ($SkipTests) {
            $cut = $text.IndexOf('#[cfg(test)]')
            if ($cut -ge 0) { $text = $text.Substring(0, $cut) }
        }
        foreach ($match in [regex]::Matches($text, $Pattern)) {
            $line = ($text.Substring(0, $match.Index) -split "`n").Count
            $failures.Add("${Label}: ${($file.FullName)}:${line}")
        }
    }
}

Test-RustPattern -Pattern '\b(WSASend|WSARecv|WSASendTo|WSARecvFrom|sendto|recvfrom)\s*\(' -Label 'non-RIO Winsock payload API' -Files $sources
Test-RustPattern -Pattern 'std::net::|TcpStream|UdpSocket|TcpListener' -Label 'non-RIO socket API' -Files $sources
Test-RustPattern -Pattern '\.unwrap\(\)|\.expect\(|panic!\(|todo!\(|unimplemented!\(|unreachable!\(' -Label 'panic in library code' -Files $sources -SkipTests

$projectFiles = $sources + @(Get-ChildItem -LiteralPath $root -File | Where-Object { $_.Name -notin @('Cargo.lock') })
Test-RustPattern -Pattern 'rust-echo-client|\bcec::' -Label 'cross-project dependency' -Files $projectFiles

if ($failures.Count -ne 0) {
    $failures | ForEach-Object { Write-Error $_ }
    throw "server source policy failed with $($failures.Count) violation(s)"
}
Write-Host 'PASS server source policy'
