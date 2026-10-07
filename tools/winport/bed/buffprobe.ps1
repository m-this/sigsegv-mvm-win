# One defender bot, one max-ammo and one max-health buff, ten re-equips, and
# sm_ap_buff_debug before, after the buff and after each re-equip. Run by
# boot.ps1 -After once the server answers rcon; needs WINBED_BOTS=1 and
# WINBED_ROOM=1 so the bot exists and the plugin holds an unlock set.
$ErrorActionPreference = 'Continue'
$out = "$env:BED\bedout"
$log = "$out\buffprobe.txt"
function Rcon($command) {
  $reply = (& bedbin\rcon.exe $command 2>&1 | Out-String).Trim()
  Add-Content $log "> $command`n$reply`n"
  return $reply
}
function Wait-For($what, $minutes, [scriptblock]$ready) {
  $until = (Get-Date).AddMinutes($minutes)
  while ((Get-Date) -lt $until) {
    $value = & $ready
    if ($value) { return $value }
    Start-Sleep 5
  }
  Add-Content $log "gave up waiting for $what"
  return $null
}

$null = Wait-For 'the plugin to hold its unlock set' 6 { (Rcon 'sm_ap_status') -match 'held' }
$bot = Wait-For 'a defender bot' 8 {
  $m = [regex]::Match((Rcon 'status'), '#\s+(\d+)\s+"[^"]*"\s+BOT')
  if ($m.Success) { $m.Groups[1].Value }
}
if (-not $bot) { exit 1 }
$target = "#$bot"
Rcon 'tf2ap_buffs_for_defender_bots 1' | Out-Null
Rcon 'tf2ap_loadout_for_bots 1' | Out-Null

Add-Content $log '=== BEFORE'
Rcon "sm_ap_buff_debug $target" | Out-Null

$granted = $false
foreach ($slot in 1, 2, 3) {
  if ((Rcon "sm_ap_buff_slot $target $slot max-ammo 1") -match 'Applied') {
    Rcon "sm_ap_buff_slot $target $slot max-health 1" | Out-Null
    $granted = $true
    break
  }
}
Add-Content $log "=== AFTER THE BUFF (granted=$granted)"
Rcon "sm_ap_buff_debug $target" | Out-Null

foreach ($swap in 1..10) {
  Add-Content $log "=== RE-EQUIP $swap"
  foreach ($slot in 'primary', 'secondary', 'melee') {
    if ((Rcon "sm_ap_loadout_set $target $slot own") -match 'is their own') { break }
  }
  Start-Sleep 2
  Rcon "sm_ap_buff_debug $target" | Out-Null
}
Add-Content $log '=== AFTER TEN RE-EQUIPS'
Rcon 'sm_ap_status' | Out-Null
Get-Content $log | ForEach-Object { Write-Host $_ }
exit 0
