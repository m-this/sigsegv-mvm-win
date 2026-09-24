# Stop the bed and gather what it left: console logs, SourceMod logs, crash
# dumps, the probe's results and the rcon dumps. The job log gets a short
# report, since it is what can be read without downloading the artifact.
param([Parameter(Mandatory)][string]$Out)
$ErrorActionPreference = 'Continue'
Get-Process srcds, winbed, cdb -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 3
$tf = "$env:BED\tf-dedicated\tf"
New-Item -ItemType Directory -Force $Out | Out-Null
Copy-Item "$env:BED\bedout\*" $Out -Recurse -ErrorAction SilentlyContinue
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

# Each crash event with the stack under it, without the module lists. The
# breakpoints are the engine noticing a debugger (DebuggerBreakIfDebugging)
# and only counted; the first two faults and the last two are printed, since
# the last one is the crash.
$cdbLogs = Get-ChildItem "$Out\cdb*.log" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime
if ($cdbLogs) {
  $log = $cdbLogs | ForEach-Object { Get-Content $_.FullName }
  # Where each module was loaded, from the lm lines the fault handler prints,
  # so a return address can be written as module+RVA: server.dll has no
  # symbols, and the export names cdb puts on its frames are the nearest
  # export, not the function.
  $bases = @{}
  foreach ($line in $log) {
    if ($line -match '^([0-9a-f]{8}) ([0-9a-f]{8}) +(server|engine|sigsegv\S*) ') { $bases[$Matches[3]] = @([Convert]::ToUInt32($Matches[1], 16), [Convert]::ToUInt32($Matches[2], 16)) }
  }
  # A frame cdb already wrote as module+offset gives that module's base too:
  # its place is the return address printed on the frame before it.
  $prev = $null
  foreach ($line in $log) {
    if ($line -match '^[0-9a-f]{8} ([0-9a-f]{8}) ') {
      if ($prev -and $line -match ' (server|engine)\+0x([0-9a-f]+)' -and -not $bases.ContainsKey($Matches[1])) {
        $base = $prev - [Convert]::ToUInt32($Matches[2], 16)
        $bases[$Matches[1]] = @($base, $base + 0x2000000)
      }
      $prev = [Convert]::ToUInt32(($line -split ' ')[1], 16)
    } else { $prev = $null }
  }
  function Rva([string]$hex) {
    $a = [Convert]::ToUInt32($hex, 16)
    foreach ($k in $bases.Keys) { if ($a -ge $bases[$k][0] -and $a -lt $bases[$k][1]) { return ('{0}+0x{1:x}' -f $k, ($a - $bases[$k][0])) } }
    return $hex
  }
  Write-Host ("cdb: {0} breakpoints passed" -f ($log | Select-String '^BREAKPOINT').Count)
  $starts = @()
  for ($i = 0; $i -lt $log.Count; $i++) {
    if ($log[$i] -match '^(FIRST-CHANCE AV|SECOND-CHANCE AV|HEAP CORRUPTION|STACK BUFFER OVERRUN|PROCESS EXIT|CPP EXCEPTION|EXIT CALLED|TERMINATE CALLED|UNHANDLED STOP)') { $starts += $i }
  }
  $pick = if ($starts.Count -le 4) { $starts } else { $starts[0, 1, -2, -1] }
  foreach ($i in $pick) {
    Write-Host "--- cdb: $($log[$i])"
    $end = [Math]::Min($log.Count - 1, $i + 140)
    for ($j = $i + 1; $j -le $end; $j++) {
      if ($log[$j] -match '^(start +end|FIRST-CHANCE|SECOND-CHANCE|PROCESS EXIT|BREAKPOINT|HEAP CORRUPTION|CPP EXCEPTION|EXIT CALLED|TERMINATE CALLED|UNHANDLED STOP)') { break }
      if ($log[$j] -match '^(eip=|\(|Access violation|Last event|  debugger time|FAULT-CODE|STACK-WORDS|ECX-WORDS|ECX-TEXT|FRAME-PARAMS|\s+[a-zA-Z_]+ = )' -or ($log[$j] -match '^[0-9a-f]{8}[ `]' -and $log[$j] -notmatch 'ntdll!|KERNEL')) {
        # A frame line is ChildEBP, RetAddr, three arguments and the frame's
        # own place; the return address is where the frame above was called.
        $ret = if ($log[$j] -match '^[0-9a-f]{8} ([0-9a-f]{8}) ') { '  (returns to ' + (Rva $Matches[1]) + ')' } else { '' }
        Write-Host (($log[$j] -replace '^[0-9a-f]{8} [0-9a-f]{8} +([0-9a-f]{8} ){3}', '' -replace ' \(FPO: [^)]*\)', '' -replace ' \(CONV: [a-z]+\)', '' -replace '/home/runner/work/sigsegv-mvm-win/sigsegv-mvm-win/', '') + $ret)
      }
    }
  }
}

# What cdb itself said last: how it ended, and any stop it was not told about.
Get-ChildItem "$Out\cdb-*.out" -ErrorAction SilentlyContinue | ForEach-Object {
  Write-Host "--- tail of $($_.Name)"
  Get-Content $_.FullName -Tail 12 | Write-Host
}
$console = Get-ChildItem "$Out\console*.log" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1
if ($console) {
  Write-Host "--- console tail, without the address table"
  Get-Content $console.FullName | Where-Object { $_ -notmatch 'AddrManager|IDetour_Sym|LoadDetours|Link FAIL|KeyValues Error|Lang, ' } |
    Select-Object -Last 12 | Write-Host
}
# Each server that stopped, its last words: a clean exit with no fatal line
# still says what it was doing, a map change, a plugin, an Error() dialog.
Get-ChildItem "$Out\consoles\console-*.log" -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object {
  Write-Host "--- last lines of $($_.Name)"
  Get-Content $_.FullName | Where-Object { $_ -notmatch 'AddrManager|IDetour_Sym|LoadDetours|Link FAIL|KeyValues Error|Lang, |\[AP\] debug|tf2_archipelago.smx\] The (death|message) request|cannot get the (unlock set|mission list)' } |
    Select-Object -Last 15 | Write-Host
}
# Every unresolved function a mission reached, across all the server's starts.
$unresolved = Get-ChildItem "$Out\consoles\*.log", "$Out\console*.log" -ErrorAction SilentlyContinue |
  Select-String -Pattern '(?:called unresolved function|virtual function) "([^"]+)"' | ForEach-Object { $_.Matches[0].Groups[1].Value } | Sort-Object -Unique
if ($unresolved) { Write-Host ("unresolved functions called: " + ($unresolved -join ', ')) }
# SigMod and tf2_archipelago both detour CTFPlayer::GetMaxAmmo. Whether the two
# still share it after SigMod reconfigures is read off these lines.
Get-ChildItem "$Out\consoles\*.log", "$Out\console*.log" -ErrorAction SilentlyContinue |
  Select-String -Pattern 'detour validation failure|probably already detoured|Make it Count' |
  ForEach-Object { $_.Line.Trim() } | Sort-Object -Unique | ForEach-Object { Write-Host "shared detour: $_" }
# Detours SigMod refused on Windows: a pop mismatch is a wrong address or a
# wrong declaration, and each one is a mechanic that does nothing.
Get-ChildItem "$Out\consoles\*.log", "$Out\console*.log" -ErrorAction SilentlyContinue |
  Select-String -Pattern 'DoLoad: "[^"]+": refused' | ForEach-Object { $_.Line.Trim() } |
  Sort-Object -Unique | ForEach-Object { Write-Host "refused detour: $_" }
Get-ChildItem "$Out\dumps" -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "dump: $($_.Name) $($_.Length)" }
# srcds catches its own crashes: it writes a minidump beside itself and exits
# cleanly, so WER sees nothing. Those dumps, and how winbed saw srcds end.
# SigMod's own record of who ended the server (ExitTrace in extension.cpp).
foreach ($f in @("$env:BED\tf-dedicated\sigsegv_exit.txt", "$env:BED\tf-dedicated\tf\sigsegv_exit.txt")) {
  if (Test-Path $f) { Write-Host "--- $f"; Get-Content $f -Tail 80 | Write-Host; Copy-Item $f $Out }
}
$mdmp = @(Get-ChildItem "$env:BED\tf-dedicated" -Recurse -Filter *.mdmp -ErrorAction SilentlyContinue) +
  @(Get-ChildItem "$env:BED\dumps\exit" -Recurse -Filter *.dmp -ErrorAction SilentlyContinue)
New-Item -ItemType Directory -Force "$Out\mdmp" | Out-Null
$mdmp | ForEach-Object { Copy-Item $_.FullName "$Out\mdmp\"; Write-Host "minidump: $($_.FullName) $($_.Length)" }
# The crash in each dump, read by cdb here: the faulting context and its stack,
# SigMod's frames named from the .pdb installed beside the extension.
$cdbExe = 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe'
if (Test-Path $cdbExe) {
  $mdmp | Select-Object -Last 2 | ForEach-Object {
    Write-Host "--- crash in $($_.Name)"
    & $cdbExe -z $_.FullName -y "$env:BED\tf-dedicated\tf\addons\sourcemod\extensions" -c ".lines -e; .ecxr; r; kv 40; ~* kv 25; lm m server; lm m engine; q" 2>&1 |
      Where-Object { $_ -match '^(eip=|[0-9a-f]{8} [0-9a-f]{8} |ExceptionAddress|ExceptionCode|Attempt to|[0-9a-f]{8} [0-9a-f]{8} +(server|engine) )' } |
      Select-Object -First 160 | Write-Host
  }
}
Get-ChildItem "$Out\winbed-*.out", "$Out\winbed-*.err" -ErrorAction SilentlyContinue | ForEach-Object {
  Write-Host "--- tail of $($_.Name)"
  Get-Content $_.FullName -Tail 6 | Write-Host
}
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
if (Test-Path "$Out\disasm.txt") {
  Write-Host '=== DISASM ==='
  Get-Content "$Out\disasm.txt" | Write-Host
}
