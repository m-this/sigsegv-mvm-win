# Start the bed's server, wait for rcon, run -Commands into bedout/, and with
# -Probe run the wave probe against it. Exits with the probe's code, or 1 when
# the server dies or never answers.
param(
  [string[]]$Commands = @(),
  [string]$Probe = '',
  [int]$BootMinutes = 20
)
$ErrorActionPreference = 'Stop'
$out = "$env:BED\bedout"
New-Item -ItemType Directory -Force $out | Out-Null
# collect.ps1 prints this last, so the verdict is at the end of the job log.
function Say($text) { Write-Host $text; Add-Content "$out\boot.txt" $text }
$env:SRCDS_RCONPW = $env:WAVEPROBE_RCONPW

$server = Start-Process bedbin\winbed.exe -ArgumentList '-serve', '-root', $env:BED `
  -RedirectStandardOutput "$out\winbed.out" -RedirectStandardError "$out\winbed.err" -PassThru

# cdb follows srcds from the moment it exists: every access violation, a heap
# corruption and the process's own exit are logged with a stack, and a crash
# leaves a full dump. srcds catches its own crashes and writes nothing useful.
$cdb = 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe'
$debugger = $null
$srcds = $null
$waitUntil = (Get-Date).AddMinutes(5)
while (-not $srcds -and (Get-Date) -lt $waitUntil -and -not $server.HasExited) {
  $srcds = Get-Process srcds -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $srcds) { Start-Sleep -Milliseconds 200 }
}
if ($srcds -and (Test-Path $cdb)) {
  $extensions = "$env:BED\tf-dedicated\tf\addons\sourcemod\extensions"
  @(
    ".logopen $out\cdb.log"
    ".sympath $extensions"
    '.reload'
    'sxe -c ".echo FIRST-CHANCE AV; r; kv 16; gn" -c2 ".echo SECOND-CHANCE AV; r; kv 60; lm; .dump /ma C:\bed\dumps\av.dmp; q" av'
    'sxe -c ".echo HEAP CORRUPTION; kv 60; .dump /ma C:\bed\dumps\heap.dmp; q" c0000374'
    'sxe -c ".echo STACK BUFFER OVERRUN; kv 60; .dump /ma C:\bed\dumps\gs.dmp; q" c0000409'
    'sxe -c ".echo PROCESS EXIT; ~* kv 30; q" epr'
    'g'
  ) | Set-Content "$out\cdb.script"
  $debugger = Start-Process $cdb -ArgumentList '-p', $srcds.Id, '-cf', "$out\cdb.script" `
    -RedirectStandardOutput "$out\cdb.out" -RedirectStandardError "$out\cdb.err" -PassThru
  Say "cdb attached to srcds $($srcds.Id)"
} else {
  Say "no debugger: srcds=$($srcds.Id) cdb=$(Test-Path $cdb)"
}

function Dead {
  if (-not $server.HasExited) { return $false }
  Say "the server exited with $($server.ExitCode)"
  Get-Content "$out\winbed.out" -Tail 80 -ErrorAction SilentlyContinue | Write-Host
  return $true
}

# srcds on a LAN reach binds rcon to the address its hostname resolves to, so
# try loopback and every IPv4 the runner has.
$candidates = @('127.0.0.1') + @(Get-NetIPAddress -AddressFamily IPv4 |
  Where-Object { $_.IPAddress -ne '127.0.0.1' } | ForEach-Object { $_.IPAddress })
$address = $null
$deadline = (Get-Date).AddMinutes($BootMinutes)
while (-not $address -and (Get-Date) -lt $deadline) {
  if (Dead) { exit 1 }
  foreach ($candidate in $candidates) {
    $env:SRCDS_RCON_HOST = $candidate
    & bedbin\rcon.exe status *> $null
    if ($LASTEXITCODE -eq 0) { $address = $candidate; break }
  }
  if (-not $address) { Start-Sleep 10 }
}
if (-not $address) { Say 'rcon never answered'; exit 1 }
Say "rcon answers on $address"
$env:SRCDS_RCON_HOST = $address

foreach ($command in $Commands) {
  $name = ($command -replace '[^a-z0-9_]', '_')
  & bedbin\rcon.exe $command > "$out\$name.txt"
  Write-Host "$command -> $out\$name.txt"
}
if ($Commands.Count -gt 0) { Get-Content "$out\sig_list_mods.txt" -ErrorAction SilentlyContinue | Write-Host }

if (-not $Probe) {
  Start-Sleep 30
  if (Dead) { exit 1 }
  exit 0
}
$arguments = @('-rcon', "${address}:27015") + ($Probe -split '\s+' | Where-Object { $_ })
& bedbin\waveprobe.exe @arguments > "$out\results.jsonl" 2> "$out\waveprobe.err"
$code = $LASTEXITCODE
Say "waveprobe exited with $code"
Get-Content "$out\waveprobe.err" -Tail 40 | ForEach-Object { Say "waveprobe: $_" }
if (Dead) { exit 1 }
& bedbin\rcon.exe sig_list_mods > "$out\sig_list_mods_after.txt"
exit $code
