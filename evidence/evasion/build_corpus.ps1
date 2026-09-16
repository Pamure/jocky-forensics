# Build a corpus of JOCKY artifacts for the evasion evaluation.
$ErrorActionPreference = 'Continue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $dir

$ok = 0
$fail = 0
foreach ($i in 1..20) {
    $out = & python -m jocky build scripts\hunt.jky -o ("art{0:d2}.build" -f $i) 2>&1
    if ($LASTEXITCODE -eq 0) { $ok++ } else { $fail++; Write-Output "build $i failed: $out" }
}
Write-Output "built=$ok failed=$fail"

# Prove the corpus is genuinely polymorphic before scanning it: if these were
# byte-identical the scan would only be testing one file twenty times.
$hashes = Get-ChildItem -Filter 'art*.build' | Get-FileHash -Algorithm SHA256 |
          Select-Object -ExpandProperty Hash
$unique = ($hashes | Sort-Object -Unique).Count
Write-Output "artifacts=$($hashes.Count) unique-sha256=$unique"

# Also a source artifact and a couple of scripts, for the scan.
Copy-Item scripts\hunt.jky hunt.jky -Force
Copy-Item scripts\quickstart.jky quickstart.jky -Force
Write-Output "sample-sizes:"
Get-ChildItem -Filter 'art*.build' | Select-Object -First 3 Name, Length | Format-Table -HideTableHeaders

# Actual compiled bytecode cache, as a control for "does Defender flag Python
# artifacts in general" rather than JOCKY specifically.
python -c "import jocky.rt.winapi" 2>$null
Write-Output "done"
