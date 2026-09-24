# Stop the bed and gather what it left: console logs, SourceMod logs, crash
# dumps, the probe's results and the rcon dumps. The job log gets a short
# report, since it is what can be read without downloading the artifact.
param([Parameter(Mandatory)][string]$Out)
$ErrorActionPreference = 'Continue'
Get-Process srcds, winbed, cdb -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 3
$tf = "$env:BED\tf-dedicated\tf"
New-Item -ItemType Directory -Force $Out | Out-Null
Copy-Item "$env:BED\bedout\*" $Out -ErrorAction SilentlyContinue
Copy-Item "$tf\console*.log" $Out -ErrorAction SilentlyContinue
Copy-Item "$tf\debug.log" $Out -ErrorAction SilentlyContinue
Copy-Item -Recurse "$tf\addons\sourcemod\logs" "$Out\sm-logs" -ErrorAction SilentlyContinue
Copy-Item -Recurse "$env:BED\dumps" "$Out\dumps" -ErrorAction SilentlyContinue

Write-Host '=== REPORT ==='
if (Test-Path "$Out\sig_list_mods.txt") {
  $mods = Get-Content "$Out\sig_list_mods.txt"
  Write-Host ("mods: {0} OK, {1} FAILED" -f ($mods | Select-String '\bOK\b').Count, ($mods | Select-String 'FAILED').Count)
}
if (Test-Path "$Out\sig_list_addrs.txt") {
  $lines = Get-Content "$Out\sig_list_addrs.txt"
  Write-Host ("addrs: {0} lines, {1} FAIL" -f $lines.Count, ($lines | Select-String 'FAIL').Count)
}

# Each debugger event with the stack under it, without the module lists.
if (Test-Path "$Out\cdb.log") {
  $log = Get-Content "$Out\cdb.log"
  $events = 0
  for ($i = 0; $i -lt $log.Count -and $events -lt 6; $i++) {
    if ($log[$i] -match '^(FIRST-CHANCE AV|SECOND-CHANCE AV|HEAP CORRUPTION|STACK BUFFER OVERRUN|PROCESS EXIT|BREAKPOINT)') {
      $events++
      Write-Host "--- cdb: $($log[$i])"
      $end = [Math]::Min($log.Count - 1, $i + 40)
      for ($j = $i + 1; $j -le $end; $j++) {
        if ($log[$j] -match '^(start +end|FIRST-CHANCE|SECOND-CHANCE|PROCESS EXIT|BREAKPOINT)') { break }
        if ($log[$j] -match '^(ChildEBP|[0-9a-f]{8} [0-9a-f]{8}|eax=|eip=|\(|[a-z_0-9]+!|Access violation)') { Write-Host $log[$j] }
      }
    }
  }
}

$console = Get-ChildItem "$Out\console*.log" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1
if ($console) {
  Write-Host "--- console tail, without the address table"
  Get-Content $console.FullName | Where-Object { $_ -notmatch 'AddrManager|IDetour_Sym|LoadDetours|Link FAIL|KeyValues Error|Lang, ' } |
    Select-Object -Last 25 | Write-Host
}
Get-ChildItem "$Out\dumps" -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "dump: $($_.Name) $($_.Length)" }
Get-Content "$Out\winbed.err" -Tail 5 -ErrorAction SilentlyContinue | Write-Host
if (Test-Path "$Out\results.jsonl") {
  Get-Content "$Out\results.jsonl" | ForEach-Object {
    try {
      $r = $_ | ConvertFrom-Json
      $why = if ($r.error) { $r.error.Substring(0, [Math]::Min(120, $r.error.Length)) } else { '' }
      Write-Host ("wave {0} w{1} {2} {3} {4}s {5}" -f $r.mission, $r.wave, $r.state, $r.outcome, [int]$r.wall_seconds, $why)
    } catch {}
  }
}
Write-Host '=== VERDICT ==='
Get-Content "$Out\boot.txt" -ErrorAction SilentlyContinue | Write-Host
