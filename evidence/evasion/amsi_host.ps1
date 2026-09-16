# Is AMSI actually functional in a real script host on this machine?
#
# This is the reference measurement for the AMSI question. If PowerShell blocks
# known-malicious script content here, then AMSI works and the direct
# AmsiScanBuffer probe from Python is the unreliable part — which is what we
# need to know before reporting anything about JOCKY and AMSI.

$ErrorActionPreference = 'Continue'

Write-Output "--- AMSI in PowerShell (a real AMSI-integrated host) ---"
$controls = @(
    'Invoke-Mimikatz -DumpCreds',
    'sekurlsa::logonpasswords',
    '[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiInitFailed","NonPublic,Static")'
)
foreach ($c in $controls) {
    try {
        Invoke-Expression $c | Out-Null
        Write-Output ("allowed : {0}" -f $c.Substring(0, [Math]::Min(50, $c.Length)))
    } catch {
        $msg = $_.Exception.Message -replace "`r?`n", ' '
        Write-Output ("BLOCKED : {0}" -f $c.Substring(0, [Math]::Min(50, $c.Length)))
        Write-Output ("          -> {0}" -f $msg.Substring(0, [Math]::Min(160, $msg.Length)))
    }
}

Write-Output ""
Write-Output "--- a JOCKY script's text, evaluated as PowerShell (should just be a syntax error) ---"
$jky = Get-Content (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'hunt.jky') -Raw
try {
    Invoke-Expression $jky | Out-Null
    Write-Output "allowed"
} catch {
    $m = $_.Exception.Message -replace "`r?`n", ' '
    Write-Output ("rejected: {0}" -f $m.Substring(0, [Math]::Min(160, $m.Length)))
}
