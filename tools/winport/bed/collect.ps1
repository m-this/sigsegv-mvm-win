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
