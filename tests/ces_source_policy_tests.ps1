Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Load the scanner alone so its regressions do not recursively run the source policy.
$policy = Join-Path $PSScriptRoot 'ces_source_policy.ps1'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($policy, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw 'source-policy script has syntax errors' }
$function = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-ProductionRust' }, $true)
if ($null -eq $function) { throw 'production Rust scanner is missing' }
. ([scriptblock]::Create($function.Extent.Text))

$fixture = @'
fn before() { let braces = "} panic!("; }
#[cfg(test)]
mod tests {
    fn allowed() { panic!("test"); let raw = r##"} {"##; }
    /* nested /* } */ { */
}
fn after<'a>(value: &'a str) { let brace = '}'; panic!("production"); }
#[cfg(test)] mod second { fn allowed() { panic!("test"); } }
fn last() { let raw = r#"panic!( and }"#; }
'@
$production = Get-ProductionRust -Text $fixture
if ([regex]::Matches($production, 'panic!\(').Count -ne 1) {
    throw 'scanner must retain production panic after the first test module and exclude only test/literal spans'
}
if ($production -notmatch 'fn after' -or $production -notmatch 'fn last') {
    throw 'scanner discarded later production items'
}
if (($production -split "`n").Count -ne ($fixture -split "`n").Count) {
    throw 'scanner changed source line numbers'
}
$rejected = $false
try { Get-ProductionRust -Text '#[cfg(test)] mod tests { fn incomplete() {' | Out-Null }
catch { $rejected = $true }
if (-not $rejected) { throw 'unterminated test module must fail closed' }
Write-Host 'PASS source-policy scanner regressions'
