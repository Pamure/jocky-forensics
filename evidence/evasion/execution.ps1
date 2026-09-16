# Does Defender interfere with JOCKY executing, and what does a run look like
# in Defender's own telemetry?
#
# Read-only with respect to system policy: no exclusions are added, real-time
# protection is not disabled, and nothing is quarantined or restored.
$ErrorActionPreference = 'Continue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $dir

function Detections { (Get-MpThreatDetection -ErrorAction SilentlyContinue | Measure-Object).Count }

$before = Detections
Write-Output "detections-before=$before"

# --- 1. execute a built artifact -------------------------------------------
Write-Output ""
Write-Output "--- jocky exec art01.build ---"
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$out = & python -m jocky exec art01.build --json 2>&1 | Out-String
$sw.Stop()
$exit = $LASTEXITCODE
Write-Output "exit=$exit elapsed_ms=$($sw.ElapsedMilliseconds) output_bytes=$($out.Length)"
$afterExec = Detections
Write-Output "detections-after-exec=$afterExec new=$($afterExec - $before)"
if ($exit -ne 0) { Write-Output "OUTPUT: $($out.Substring(0, [Math]::Min(400, $out.Length)))" }

# --- 2. a full collection run ----------------------------------------------
Write-Output ""
Write-Output "--- jocky run scripts\hunt.jky ---"
$sw2 = [System.Diagnostics.Stopwatch]::StartNew()
$out2 = & python -m jocky run scripts\hunt.jky 2>&1 | Out-String
$sw2.Stop()
$exit2 = $LASTEXITCODE
Write-Output "exit=$exit2 elapsed_ms=$($sw2.ElapsedMilliseconds) findings_lines=$(($out2 -split "`n").Count)"
$afterRun = Detections
Write-Output "detections-after-run=$afterRun new=$($afterRun - $afterExec)"

# --- 3. the most 'suspicious looking' thing JOCKY does ---------------------
# Reading another process's memory is what an EDR watches hardest. Do it
# deliberately and see whether Defender reacts.
Write-Output ""
Write-Output "--- process-memory reads across the process table ---"
$probe = @'
import sys
from jocky.rt import winapi
rows = winapi.list_processes()
denied = [r for r in rows if r.get("access_denied")]
print("processes=%d readable=%d denied=%d" % (len(rows), len(rows) - len(denied), len(denied)))
print("denials_recorded=%d" % len(winapi.access_errors()))
'@
$probe | Out-File -Encoding ASCII probe_mem.py
$out3 = & python probe_mem.py 2>&1 | Out-String
Write-Output $out3.Trim()
$afterProbe = Detections
Write-Output "detections-after-probe=$afterProbe new=$($afterProbe - $afterRun)"

# --- 4. what Defender logged during all of that ----------------------------
Write-Output ""
Write-Output "--- Defender operational events in the last 15 minutes ---"
$since = (Get-Date).AddMinutes(-15)
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Windows Defender/Operational'
        StartTime = $since
    } -ErrorAction Stop
    Write-Output "event-count=$($events.Count)"
    $events | Select-Object -First 8 |
        ForEach-Object { Write-Output ("  id={0} {1}" -f $_.Id, $_.Message.Split("`n")[0]) }
} catch {
    Write-Output "no events or log unavailable: $($_.Exception.Message)"
}

Write-Output ""
Write-Output "detections-final=$(Detections) (started at $before)"
Write-Output "NET-NEW-DETECTIONS-ACROSS-ALL-JOCKY-ACTIVITY=$((Detections) - $before)"
