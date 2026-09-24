# Stop the bed and gather what it left: console logs, SourceMod logs, crash
# dumps, the probe's results and the rcon dumps.
param([Parameter(Mandatory)][string]$Out)
$ErrorActionPreference = 'Continue'
Get-Process srcds, winbed -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 3
$tf = "$env:BED\tf-dedicated\tf"
New-Item -ItemType Directory -Force $Out | Out-Null
Copy-Item "$env:BED\bedout\*" $Out -ErrorAction SilentlyContinue
Copy-Item "$tf\console*.log" $Out -ErrorAction SilentlyContinue
Copy-Item "$tf\debug.log" $Out -ErrorAction SilentlyContinue
Copy-Item "$env:BED\tf-dedicated\debug.log" "$Out\debug-root.log" -ErrorAction SilentlyContinue
Copy-Item -Recurse "$tf\addons\sourcemod\logs" "$Out\sm-logs" -ErrorAction SilentlyContinue
Copy-Item -Recurse "$env:BED\dumps" "$Out\dumps" -ErrorAction SilentlyContinue
Get-ChildItem -Recurse $Out | Select-Object FullName, Length | Format-Table -AutoSize | Out-String -Width 200 | Write-Host

# The job log is what can be read without downloading the artifact, so the
# findings go there too.
if (Test-Path "$Out\results.jsonl") {
  Write-Host '=== WAVES ==='
  Get-Content "$Out\results.jsonl" | ForEach-Object {
    try {
      $r = $_ | ConvertFrom-Json
      $error_text = if ($r.error) { $r.error.Substring(0, [Math]::Min(160, $r.error.Length)) } else { '' }
      Write-Host ("WAVE {0} w{1} {2} {3} bots={4}/{5} tanks={6}/{7} {8}s {9}" -f $r.mission, $r.wave, $r.state, $r.outcome, $r.bots, $r.bot_spawns, $r.tanks, $r.tank_spawns, [int]$r.wall_seconds, $error_text)
    } catch { Write-Host "UNPARSED $_" }
  }
}
foreach ($file in 'sig_list_mods.txt', 'sig_list_mods_after.txt') {
  if (Test-Path "$Out\$file") { Write-Host "=== $file ==="; Get-Content "$Out\$file" | Write-Host }
}
if (Test-Path "$Out\sig_list_addrs.txt") {
  $lines = Get-Content "$Out\sig_list_addrs.txt"
  Write-Host ("=== sig_list_addrs: {0} lines, {1} FAIL ===" -f $lines.Count, ($lines | Select-String 'FAIL').Count)
}
$console = Get-ChildItem "$Out\console*.log" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1
if ($console) {
  Write-Host "=== $($console.Name): warnings ==="
  Get-Content $console.FullName | Select-String -Pattern 'FAIL|error|Error|crash|unresolved|Parse Failed|Unknown attribute|Invalid populator|SigMod|sigsegv' |
    Select-Object -First 400 | ForEach-Object { Write-Host $_.Line }
  Write-Host "=== $($console.Name): tail ==="
  Get-Content $console.FullName -Tail 120 | Write-Host
}
Get-ChildItem "$Out\sm-logs\errors_*.log" -ErrorAction SilentlyContinue | ForEach-Object {
  Write-Host "=== $($_.Name) ==="; Get-Content $_.FullName -Tail 150 | Write-Host
}
Get-ChildItem "$Out\dumps" -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "DUMP $($_.Name) $($_.Length)" }
foreach ($file in 'debug.log', 'debug-root.log') {
  if (Test-Path "$Out\$file") { Write-Host "=== $file ==="; Get-Content "$Out\$file" -Tail 80 | Write-Host }
}
