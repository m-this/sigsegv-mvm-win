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
Get-PSDrive C | Format-Table -AutoSize | Out-String | Write-Host
