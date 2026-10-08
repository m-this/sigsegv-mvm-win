# One RED bot, one max-ammo and one max-health buff, ten re-equips, and
# sm_ap_buff_debug before, after the buff, after each re-equip and five seconds
# later. Run by boot.ps1 -After once the server answers rcon; needs WINBED_BOTS=1
# and WINBED_ROOM=1 so the defender mod and the unlock set are there. The bot
# comes from tf_bot_add between waves, which the defender mod takes over.
# Short on purpose: an idle srcds on the bed ends itself with the console's
# GetLine fatal after about eight minutes.
$ErrorActionPreference = 'Continue'
$out = "$env:BED\bedout"
$log = "$out\buffprobe.txt"
function Rcon($command) {
  $reply = (& bedbin\rcon.exe $command 2>&1 | Out-String).Trim()
  Add-Content $log "> $command`n$reply`n"
  return $reply
}
function Say($text) { Add-Content $log $text; Write-Host $text }
function Wait-For($what, $seconds, [scriptblock]$ready) {
  $until = (Get-Date).AddSeconds($seconds)
  while ((Get-Date) -lt $until) {
    $value = & $ready
    if ($value) { return $value }
    Start-Sleep 3
  }
  Say "gave up waiting for $what"
  return $null
}
function Bot-Id {
  $m = [regex]::Match((Rcon 'status'), '#\s+(\d+)\s+"[^"]*"\s+BOT')
  if ($m.Success) { return $m.Groups[1].Value }
}

$null = Wait-For 'the plugin to hold its unlock set' 60 { (Rcon 'sm_ap_status') -match 'held' }
Start-Sleep 10
Rcon 'tf2ap_buffs_for_defender_bots 1' | Out-Null
Rcon 'tf2ap_loadout_for_bots 1' | Out-Null
Rcon 'tf_bot_add 1 red heavy' | Out-Null
$bot = Wait-For 'a bot on the server' 60 { Bot-Id }
if (-not $bot) { exit 1 }
Start-Sleep 5
$bot = Bot-Id
$target = "#$bot"
Say "bot userid $bot"

Say '=== BEFORE'
Rcon "sm_ap_buff_debug $target" | Out-Null

$granted = $false
foreach ($slot in 1, 2, 3) {
  if ((Rcon "sm_ap_buff_slot $target $slot max-ammo 1") -match 'Applied') {
    Rcon "sm_ap_buff_slot $target $slot max-health 1" | Out-Null
    $granted = $true
    break
  }
}
Say "=== AFTER THE BUFF (granted=$granted)"
Rcon "sm_ap_buff_debug $target" | Out-Null

# The first weapon the bot's class lists that the plugin accepts; "own" puts it back.
$other = $null
foreach ($name in 'Natascha', 'Tomislav', '"Brass Beast"', 'Scattergun', '"Rocket Launcher"', '"Sniper Rifle"') {
  if ((Rcon "sm_ap_loadout_set $target primary $name") -match 'primary is ') { $other = $name; break }
}
Say "alternate primary: $other"
foreach ($swap in 1..10) {
  Say "=== RE-EQUIP $swap"
  $wanted = if ($other -and $swap % 2 -eq 0) { $other } else { 'own' }
  Rcon "sm_ap_loadout_set $target primary $wanted" | Out-Null
  Start-Sleep 2
  Rcon "sm_ap_buff_debug $target" | Out-Null
}
Say '=== AFTER TEN RE-EQUIPS'
Rcon "sm_ap_buff_debug $target" | Out-Null
Start-Sleep 5
Say '=== FIVE SECONDS LATER'
Rcon "sm_ap_buff_debug $target" | Out-Null
exit 0
