# The load check, played on the installed server: the extension loads on a
# ServerVersion its table was not made for when the binaries are the same, and
# refuses, naming the binary, when one is not or has no identity. Each case
# boots on a copy of windows.txt changed one way. Steam serves only the
# current build, so the table is what changes, not the game.
# Run after boot.ps1; leaves windows.txt, console.log and boot.txt as they were.
$ErrorActionPreference = 'Stop'
$out = "$env:BED\bedout"
$tf = "$env:BED\tf-dedicated\tf"
$table = "$tf\addons\sourcemod\gamedata\sigsegv\windows.txt"
$original = [IO.File]::ReadAllText($table)
$build = [regex]::Match($original, 'ServerVersion (\d+),').Groups[1].Value
$server = [regex]::Match($original, '"sigsegv binary server" "0x([0-9a-f]+) (0x[0-9a-f]+)"')
if (-not $build -or -not $server.Success) { throw "windows.txt has no build header or no identity for server.dll" }
$stamp = [Convert]::ToUInt32($server.Groups[1].Value, 16) + 1

$cases = @(
  @{ Name = 'another-build'; Loads = $true
     Table = $original.Replace("build ""$build""", 'build "1"').Replace("ServerVersion $build,", 'ServerVersion 1,')
     Expect = 'address table made for ServerVersion 1, the server is \d+; the 6 binaries it reads are the same' }
  @{ Name = 'server-stamp'; Loads = $false
     Table = $original.Replace($server.Value, ('"sigsegv binary server" "0x{0:x} {1}"' -f $stamp, $server.Groups[2].Value))
     Expect = ('server\.dll is TimeDateStamp 0x{0:x} SizeOfImage {1}, the address table for ServerVersion {2} was made from 0x{3:x} ' -f ($stamp - 1), $server.Groups[2].Value, $build, $stamp) }
  @{ Name = 'server-missing'; Loads = $false
     Table = [regex]::Replace($original, '[ \t]*"sigsegv binary server"[^\n]*\n', '')
     Expect = 'the address table has addresses in server\.dll and no identity for it' }
)

function Stop-Bed {
  Get-Process srcds, winbed -ErrorAction SilentlyContinue | Stop-Process -Force
  Get-Process srcds -ErrorAction SilentlyContinue | Wait-Process -Timeout 60 -ErrorAction SilentlyContinue
}

New-Item -ItemType Directory -Force "$out\identity" | Out-Null
$bootLog = [IO.File]::ReadAllText("$out\boot.txt")
Stop-Bed
Move-Item "$tf\console.log" "$tf\console-boot.log"
$failed = @()
try {
  foreach ($case in $cases) {
    if ($case.Table -eq $original) { throw "$($case.Name): the change did not apply to windows.txt" }
    [IO.File]::WriteAllText($table, $case.Table)
    & "$PSScriptRoot\boot.ps1"
    $code = $LASTEXITCODE
    $alive = [bool](Get-Process srcds -ErrorAction SilentlyContinue)
    $exts = if ($alive) { @(& bedbin\rcon.exe 'sm exts list') -join "`n" } else { '' }
    # srcds holds its logs open with no sharing: read them once it is gone.
    Stop-Bed
    $console = "$out\identity\$($case.Name).log"
    if (Test-Path "$tf\console.log") { Move-Item "$tf\console.log" $console } else { Set-Content $console '' }
    $errors = @(Get-ChildItem "$tf\addons\sourcemod\logs\errors_*.log" -ErrorAction SilentlyContinue |
      ForEach-Object { [IO.File]::ReadAllText($_.FullName) }) -join "`n"
    $found = [regex]::Match("$exts`n$([IO.File]::ReadAllText($console))`n$errors", $case.Expect)
    Set-Content "$out\identity\$($case.Name).exts.txt" $exts

    $verdict = if ($case.Loads) { $code -eq 0 } else { $code -ne 0 -and $alive }
    $line = "$($case.Name): exit $code, server $(if ($alive) { 'up' } else { 'gone' }), " +
      $(if ($found.Success) { "says: $($found.Value)" } else { "no line matches: $($case.Expect)" })
    Write-Host $line
    Add-Content "$out\identity.txt" $line
    if (-not ($verdict -and $found.Success)) { $failed += $case.Name }
  }
} finally {
  Stop-Bed
  if (Test-Path "$tf\console.log") { Move-Item -Force "$tf\console.log" "$out\identity\interrupted.log" }
  [IO.File]::WriteAllText($table, $original)
  [IO.File]::WriteAllText("$out\boot.txt", $bootLog)
  Move-Item "$tf\console-boot.log" "$tf\console.log"
}
if ($failed) { Write-Host "the load check did not hold: $($failed -join ', ')"; exit 1 }
