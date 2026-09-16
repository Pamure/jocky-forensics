# A real collection run inside a running Defender process, followed immediately
# by a log sweep, on a live host with no special privileges.

$ErrorActionPreference = 'Continue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Get-Baseline {
  $cut = (Get-Date).AddMinutes(-5)
  try {
    (Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; StartTime=$cut} -MaxEvents 200 -ErrorAction Stop)
  } catch { $null }
}

function Report-Infra {
  $status = Get-MpComputerStatus
  "AMService: {0}, RealTimeProtection: {1}, BehaviourMonitoring: {2}, OnAccessProtection: {3}, WdisEnableEnforcement: {4}, FullScanAge(hours): {5}" -f `
    $status.AMServiceEnabled, $status.RealTimeProtectionEnabled, $status.BehaviorMonitorEnabled, $status.OnAccessProtectionEnabled, $status.RealTimeScanEnabledFallback, $status.FullScanAgeHours
}

$beforeLog = Get-Baseline
$beforeCount = (@($beforeLog) | Measure-Object).Count
Write-Output "baseline events in last 5 min: $beforeCount"
Report-Infra
Write-Output ""

Write-Output "--- full collection run ---"
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$out = & python -m jocky run scripts\hunt.jky 2>&1 | Out-String
$code = $LASTEXITCODE
$sw.Stop()
Write-Output "jocky exit=$code elapsed_ms=$($sw.ElapsedMilliseconds) findings=$($out.Trim().Length)"
Write-Output ""

Write-Output "--- reading other processes' memory at scale ---"
$probe = @'
import sys, json
sys.path.insert(0, '.')
from jocky.rt import winapi
rows = winapi.list_processes()
seen, denied = [], 0
for r in rows:
    h = winapi._open_process(r["pid"])
    if h:
        seen.append(r["pid"])
        winapi._close(h)
    else:
        denied += 1
print(json.dumps({"opened": len(seen), "denied": denied, "total": len(rows)}))
'@
$probe | Out-File -Encoding ascii memprobe.py -Force
$out2 = & python memprobe.py 2>&1
Write-Output "memprobe: $out2"

$afterLog = Get-Baseline
$afterCount = (@($afterLog) | Measure-Object).Count
$new = @($afterLog) | Where-Object { $_.TimeCreated -gt ($beforeLog | Measure-Object -Property TimeCreated -Maximum).Maximum }
if (-not $new) { $new = @() }
if ($beforeCount -eq 0) {
  Write-Output "no Defender events 5 minutes before the run, and none since baseline -> no detection"
} else {
  Write-Output "new events during run: $($new.Count)"
  $new | ForEach-Object { Write-Output ("  id={0} {1}" -f $_.Id, $_.Message.Split("`n")[0]) }
}

Write-Output ""
Write-Output "=== stored confirmation of no-detections ==="
$dets = Get-MpThreatDetection -ErrorAction SilentlyContinue
"total detections on host: {0}" -f ($dets | Measure-Object).Count
$dets | Select-Object -First 3 | ForEach-Object { "  {0} {1}" -f $_.ThreatID, $_.InitialDetectionTime }
