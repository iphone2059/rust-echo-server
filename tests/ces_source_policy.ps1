param(
    [Parameter(Mandatory)]
    [string] $ProjectRoot
)

# Source policy of the Rust server, mirroring cpp-echo-server/tests/ces_source_policy.ps1:
# the data path is RIO only, the library never panics on a failure, and no project borrows
# from a sibling port. Only the body of a #[cfg(test)] module is exempt from the
# panic rule; production items following that module remain covered.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path -LiteralPath $ProjectRoot).Path
$sources = @(Get-ChildItem -LiteralPath (Join-Path $root 'src') -File -Recurse | Where-Object { $_.Extension -eq '.rs' })
$failures = [System.Collections.Generic.List[string]]::new()

function Get-ProductionRust {
    param([string] $Text)
    # Mask comments and literals before counting braces. Preserve offsets and newlines
    # so diagnostics still point at the original source lines.
    $mask = $Text.ToCharArray()
    $index = 0
    while ($index -lt $Text.Length) {
        $start = $index
        $length = 0
        if ($index + 1 -lt $Text.Length -and $Text[$index] -eq '/' -and $Text[$index + 1] -eq '/') {
            $end = $Text.IndexOf("`n", $index)
            $length = if ($end -lt 0) { $Text.Length - $index } else { $end - $index }
        } elseif ($index + 1 -lt $Text.Length -and $Text[$index] -eq '/' -and $Text[$index + 1] -eq '*') {
            $depth = 1
            $cursor = $index + 2
            while ($cursor -lt $Text.Length - 1 -and $depth -gt 0) {
                $pair = $Text.Substring($cursor, 2)
                if ($pair -eq '/*') { $depth++; $cursor += 2 }
                elseif ($pair -eq '*/') { $depth--; $cursor += 2 }
                else { $cursor++ }
            }
            if ($depth -ne 0) { throw 'source policy: unterminated Rust block comment' }
            $length = $cursor - $index
        } elseif (($Text[$index] -eq 'r') -and ($Text.Substring($index) -match '^r(#{0,255})"')) {
            $opening = $Matches[0].Length
            $closing = '"' + $Matches[1]
            $end = $Text.IndexOf($closing, $index + $opening, [StringComparison]::Ordinal)
            if ($end -lt 0) { throw 'source policy: unterminated Rust raw string' }
            $length = $end + $closing.Length - $index
        } elseif ($Text[$index] -eq '"') {
            $cursor = $index + 1
            while ($cursor -lt $Text.Length) {
                if ($Text[$cursor] -eq '\') { $cursor += 2; continue }
                if ($Text[$cursor] -eq '"') { $cursor++; break }
                $cursor++
            }
            $length = $cursor - $index
        } elseif ($Text[$index] -eq "'" -and ($Text.Substring($index) -match "^'(?:\\u\{[0-9a-fA-F_]+\}|\\x[0-9a-fA-F]{2}|\\.|[^'\\\r\n])'")) {
            $length = $Matches[0].Length
        }
        if ($length -gt 0) {
            for ($cursor = $start; $cursor -lt $start + $length; $cursor++) {
                if ($mask[$cursor] -notin @("`r", "`n")) { $mask[$cursor] = ' ' }
            }
            $index += $length
        } else { $index++ }
    }
    $code = -join $mask
    foreach ($attribute in [regex]::Matches($code, '#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]')) {
        $tail = $code.Substring($attribute.Index + $attribute.Length)
        $module = [regex]::Match($tail, '^\s*mod\s+\w+\s*\{')
        if (-not $module.Success) { throw 'source policy: cfg(test) must annotate an inline module' }
        $opening = $attribute.Index + $attribute.Length + $module.Length - 1
        $depth = 1
        $cursor = $opening + 1
        while ($cursor -lt $code.Length -and $depth -gt 0) {
            if ($code[$cursor] -eq '{') { $depth++ }
            elseif ($code[$cursor] -eq '}') { $depth-- }
            $cursor++
        }
        if ($depth -ne 0) { throw 'source policy: unterminated test module' }
        for ($position = $attribute.Index; $position -lt $cursor; $position++) {
            if ($mask[$position] -notin @("`r", "`n")) { $mask[$position] = ' ' }
        }
    }
    return -join $mask
}

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
            $text = Get-ProductionRust -Text $text
        }
        foreach ($match in [regex]::Matches($text, $Pattern)) {
            $line = ($text.Substring(0, $match.Index) -split "`n").Count
            $failures.Add("${Label}: $($file.FullName):${line}")
        }
    }
}

& (Join-Path $PSScriptRoot 'ces_source_policy_tests.ps1')

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
