# Evasion evaluation harness — SIH26148 deliverable 5.
#
# Measures whether JOCKY's artifacts are flagged by the endpoint protection on
# this host. Read-only with respect to the system: it does NOT disable
# real-time protection, does NOT add exclusions, and does NOT modify Defender
# policy. It writes test files into its own temp directory and scans them.
#
# The EICAR block is a POSITIVE CONTROL. Without it, "no detections" would be
# indistinguishable from "the harness does not work" — the standard way a
# security product's own test suite is invalidated.

$ErrorActionPreference = 'Continue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$mp = Get-ChildItem 'C:\ProgramData\Microsoft\Windows Defender\Platform' -Directory |
      Sort-Object Name | Select-Object -Last 1
$mpcmd = Join-Path $mp.FullName 'MpCmdRun.exe'

function Get-DetectionCount {
    try { return (Get-MpThreatDetection -ErrorAction SilentlyContinue | Measure-Object).Count }
    catch { return -1 }
}

function Scan-One([string]$path) {
    # Targeted scan of a single file. Exit code 0 = clean, 2 = threat found.
    $out = & $mpcmd -Scan -ScanType 3 -File $path -DisableRemediation 2>&1 | Out-String
    $code = $LASTEXITCODE
    return @{ exit = $code; output = $out.Trim() }
}

Write-Output "defender-platform=$($mp.Name)"
Write-Output "signature-version=$((Get-MpComputerStatus).AntivirusSignatureVersion)"
Write-Output "realtime-protection=$((Get-MpComputerStatus).RealTimeProtectionEnabled)"
Write-Output ""

# ---------------------------------------------------------------- control
$before = Get-DetectionCount
Write-Output "detections-before=$before"

$eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
$eicarPath = Join-Path $dir 'eicar.com'
Set-Content -Path $eicarPath -Value $eicar -Encoding ASCII -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3
$afterEicar = Get-DetectionCount
$eicarGone = -not (Test-Path $eicarPath)
Write-Output "eicar-on-disk-after-3s=$(-not $eicarGone)"
Write-Output "detections-after-eicar=$afterEicar"
if (($afterEicar -gt $before) -or $eicarGone) {
    Write-Output "POSITIVE-CONTROL=PASS  (the harness detects a known-bad file)"
} else {
    Write-Output "POSITIVE-CONTROL=FAIL  (results below are meaningless)"
}
Remove-Item $eicarPath -Force -ErrorAction SilentlyContinue
Write-Output ""

# ---------------------------------------------------------------- artifacts
Write-Output "--- scanning JOCKY artifacts ---"
$artifacts = Get-ChildItem -Path $dir -Filter '*.build' -ErrorAction SilentlyContinue
if (-not $artifacts) { Write-Output "no artifacts found; run the build step first" }
foreach ($a in $artifacts) {
    $r = Scan-One $a.FullName
    Write-Output ("{0} bytes={1} scan-exit={2}" -f $a.Name, $a.Length, $r.exit)
    if ($r.exit -ne 0) {
        Write-Output "  OUTPUT: $($r.output)"
    }
}
Write-Output ""

# ---------------------------------------------------------------- sources
Write-Output "--- scanning JOCKY source and package ---"
$targets = @()
$targets += Get-ChildItem -Path (Join-Path $dir 'scripts') -Filter '*.jky' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 5
$targets += Get-ChildItem -Path (Join-Path $dir 'jocky') -Filter '*.py' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 5
foreach ($t in $targets) {
    $r = Scan-One $t.FullName
    Write-Output ("{0} scan-exit={1}" -f $t.Name, $r.exit)
}
Write-Output ""

$final = Get-DetectionCount
Write-Output "detections-final=$final"
Write-Output "net-new-detections=$($final - $afterEicar)"
Write-Output ""
Write-Output "--- recent detection history ---"
Get-MpThreatDetection -ErrorAction SilentlyContinue |
    Select-Object -First 5 ThreatID, InitialDetectionTime, Resources |
    Format-List
