# Install the bed: the game, SourceMod, the community packs, this build of
# SigMod and the probe plugin, the way tf2-archipelago's launcher installs them.
# Expects BED (the install root), the package in pkg/ and the tools in bedbin/.
$ErrorActionPreference = 'Stop'
Get-PSDrive C | Format-Table -AutoSize | Out-String | Write-Host

& bedbin\winbed.exe -install -root $env:BED -sigmod pkg\package-windows.zip -probe bedbin\tf2_waveprobe.smx
if ($LASTEXITCODE) { exit $LASTEXITCODE }

# A crash leaves a minidump behind: srcds under Breakpad wrote none for SAM.
$wer = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\srcds.exe'
New-Item -Force $wer | Out-Null
New-Item -ItemType Directory -Force "$env:BED\dumps" | Out-Null
Set-ItemProperty $wer DumpFolder "$env:BED\dumps" -Type ExpandString
Set-ItemProperty $wer DumpType 1 -Type DWord
Set-ItemProperty $wer DumpCount 10 -Type DWord

# A server that ends itself (exit, ExitProcess, the engine's Error) leaves no
# crash and no dump, and SigMod's servers were ending with status 100 a second
# into a mission. Silent process exit monitoring dumps the process at that
# moment, with the stack of the thread that asked to exit.
$spe = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\srcds.exe'
New-Item -Force $spe | Out-Null
New-Item -ItemType Directory -Force "$env:BED\dumps\exit" | Out-Null
Set-ItemProperty $spe ReportingMode 2 -Type DWord
Set-ItemProperty $spe LocalDumpFolder "$env:BED\dumps\exit" -Type String
Set-ItemProperty $spe DumpType 0 -Type DWord
$ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\srcds.exe'
New-Item -Force $ifeo | Out-Null
$flags = (Get-ItemProperty $ifeo -Name GlobalFlag -ErrorAction SilentlyContinue).GlobalFlag
Set-ItemProperty $ifeo GlobalFlag ([int]$flags -bor 0x200) -Type DWord
Get-PSDrive C | Format-Table -AutoSize | Out-String | Write-Host

# The debugger in boot.ps1 names SigMod's functions from this.
$pdb = 'pkg\sigsegv.ext.2.tf2.pdb'
if (Test-Path $pdb) {
  Copy-Item $pdb "$env:BED\tf-dedicated\tf\addons\sourcemod\extensions\"
}
