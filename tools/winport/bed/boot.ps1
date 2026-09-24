# Start the bed's server, wait for rcon, run -Commands into bedout/, and with
# -Probe play the probe's plan one mission at a time. A server that dies is
# started again before the next mission and the reason is written down, so one
# run finds every mission that stops the server rather than the first one.
# Exits with 1 when any mission failed or the server never answered.
param(
  [string[]]$Commands = @(),
  [string]$Probe = '',
  [int]$BootMinutes = 20,
  [int]$MaxStarts = 40
)
$ErrorActionPreference = 'Stop'
$out = "$env:BED\bedout"
$tf = "$env:BED\tf-dedicated\tf"
New-Item -ItemType Directory -Force $out, "$out\consoles" | Out-Null
# collect.ps1 prints this last, so the verdict is at the end of the job log.
function Say($text) { Write-Host $text; Add-Content "$out\boot.txt" $text }
$env:SRCDS_RCONPW = $env:WAVEPROBE_RCONPW
$cdb = 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe'
$script:server = $null
$script:starts = 0
$script:address = $null
$script:srcdsId = $null

function Attach-Debugger($srcds, $n) {
  # cdb follows srcds from the moment it exists: every access violation, a
  # heap corruption and the process's own exit are logged with a stack. srcds
  # catches its own crashes and writes nothing useful.
  $extensions = "$tf\addons\sourcemod\extensions"
  $log = if ($n -eq 1) { "$out\cdb.log" } else { "$out\cdb-$n.log" }
  @(
    ".logopen $log"
    ".sympath $extensions"
    '.lines -e'
    '.reload'
    # Nothing stops the process except what is named below: the engine calls
    # DebuggerBreakIfDebugging (int 3) once it sees a debugger, and a stopped
    # cdb reading an empty stdin is a server that never answers rcon.
    'sxn *'
    'sxe -c ".echo BREAKPOINT; kv 20; gh" bpe'
    'sxe -c ".echo FIRST-CHANCE AV; r; kv 16; .echo FAULT-CODE; u @eip-10 L8; .echo STACK-WORDS; dps @esp L16; .echo ECX-WORDS; dd @ecx L12; .echo ECX-TEXT; da @ecx L40; .echo FRAME-PARAMS; kP 12; .echo MODULE-BASES; lm m server; lm m engine; lm m sigsegv*; gn" -c2 ".echo SECOND-CHANCE AV; r; kv 60; lm; q" av'
    'sxe -c ".echo HEAP CORRUPTION; kv 60; q" c0000374'
    'sxe -c ".echo STACK BUFFER OVERRUN; kv 60; q" c0000409'
    'sxe -c ".echo PROCESS EXIT; ~* kv 30; q" epr'
    'g'
  ) | Set-Content "$out\cdb-$n.script"
  Start-Process $cdb -ArgumentList '-p', $srcds.Id, '-cf', "$out\cdb-$n.script" `
    -RedirectStandardOutput "$out\cdb-$n.out" -RedirectStandardError "$out\cdb-$n.err" | Out-Null
}

# The srcds this script started and attached to, not winbed, which can
# outlive it, and not whatever srcds is running, which after a crash can be a
# fresh one no debugger is on.
function Alive { return $script:srcdsId -and [bool](Get-Process -Id $script:srcdsId -ErrorAction SilentlyContinue) }

# Why the last server stopped, from the console it left: the unresolved
# function SigMod refused to call, or the last lines before it went quiet.
function Death-Reason {
  $console = "$tf\console.log"
  if (-not (Test-Path $console)) { return 'no console' }
  $fatal = Select-String -Path $console -Pattern 'called unresolved function|FATAL ERROR|Host_Error|Sys_Error' |
    Select-Object -Last 1
  if ($fatal) { return $fatal.Line.Trim() }
  return 'no fatal line; last: ' + ((Get-Content $console -Tail 1) -join ' ')
}

function Start-Bed {
  if ($script:starts -ge $MaxStarts) { return $false }
  $script:starts++
  $n = $script:starts
  if (Test-Path "$tf\console.log") { Copy-Item "$tf\console.log" "$out\consoles\console-$($n - 1).log" }
  Get-Process srcds, winbed -ErrorAction SilentlyContinue | Stop-Process -Force
  $script:server = Start-Process bedbin\winbed.exe -ArgumentList '-serve', '-root', $env:BED `
    -RedirectStandardOutput "$out\winbed-$n.out" -RedirectStandardError "$out\winbed-$n.err" -PassThru
  $srcds = $null
  $until = (Get-Date).AddMinutes(5)
  while (-not $srcds -and (Get-Date) -lt $until -and -not $script:server.HasExited) {
    $srcds = Get-Process srcds -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $srcds) { Start-Sleep -Milliseconds 200 }
  }
  $script:srcdsId = if ($srcds) { $srcds.Id } else { $null }
  if ($srcds -and (Test-Path $cdb)) { Attach-Debugger $srcds $n }
  # srcds on a LAN reach binds rcon to the address its hostname resolves to,
  # so try loopback and every IPv4 the runner has.
  $candidates = @('127.0.0.1') + @(Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -ne '127.0.0.1' } | ForEach-Object { $_.IPAddress })
  $deadline = (Get-Date).AddMinutes($BootMinutes)
  while ((Get-Date) -lt $deadline) {
    if (-not (Alive)) { Say "start ${n}: the server exited while booting: $(Death-Reason)"; return $false }
    foreach ($candidate in $candidates) {
      $env:SRCDS_RCON_HOST = $candidate
      & bedbin\rcon.exe status *> $null
      if ($LASTEXITCODE -eq 0) { $script:address = $candidate; return $true }
    }
    Start-Sleep 10
  }
  Say "start ${n}: rcon never answered"
  return $false
}

if (-not (Start-Bed)) { exit 1 }
Say "rcon answers on $($script:address)"
foreach ($command in $Commands) {
  $name = ($command -replace '[^a-z0-9_]', '_')
  & bedbin\rcon.exe $command > "$out\$name.txt"
}

if (-not $Probe) {
  Start-Sleep 30
  if (-not (Alive)) { Say "the server died after booting: $(Death-Reason)"; exit 1 }
  exit 0
}

$probeArgs = @($Probe -split '\s+' | Where-Object { $_ })
$missions = & bedbin\waveprobe.exe -plan @probeArgs | ForEach-Object { ($_ | ConvertFrom-Json).mission } | Select-Object -Unique
$single = @()
for ($i = 0; $i -lt $probeArgs.Count; $i++) {
  # A named mission needs no shard or SigMod filter.
  if ($probeArgs[$i] -in '-shards', '-shard') { $i++; continue }
  if ($probeArgs[$i] -eq '-only-sigmod') { continue }
  $single += $probeArgs[$i]
}
# The probe cannot play reverse MvM (it has no BLU objective simulator) and
# refuses one by name, so those are counted rather than failed.
$reverse = @($missions | Where-Object { $_ -like '*_rev_*' })
$missions = @($missions | Where-Object { $_ -notlike '*_rev_*' })
Say "$($missions.Count) missions in this shard, $($reverse.Count) reverse ones left out"
$failed = 0
foreach ($mission in $missions) {
  if (-not (Alive) -and -not (Start-Bed)) { Say "giving up at ${mission}: the server does not start"; $failed++; break }
  & bedbin\waveprobe.exe -rcon "$($script:address):27015" -mission $mission @single >> "$out\results.jsonl" 2>> "$out\waveprobe.err"
  if ($LASTEXITCODE -ne 0) { $failed++ }
  if (-not (Alive)) { Say "died in ${mission}: $(Death-Reason)" }
}
Copy-Item "$tf\console.log" "$out\consoles\console-$($script:starts).log" -ErrorAction SilentlyContinue
Say "$failed of $($missions.Count) missions failed, $($script:starts) server starts"
if ($failed -gt 0) { exit 1 }
exit 0
