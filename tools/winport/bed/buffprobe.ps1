# One RED defender bot with an ammo-using weapon in hand, buffed with max-ammo
# and max-health, then rebuilt ten times in a row with no regeneration between
# (sm_ap_buff_rebuild), in two phases: A with the plugin's restore of the ammo and
# health a rebuild raises off, C with it on. Run by boot.ps1 -After once the server
# answers rcon; needs WINBED_BOTS=1 and WINBED_ROOM=1. The bot comes from
# tf_bot_add between waves, which the defender mod takes over. Short on purpose:
# an idle srcds on the bed ends itself with the console's GetLine fatal after
# about eight minutes.
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
function Bot-Ids {
  return @([regex]::Matches((Rcon 'status'), '#\s+(\d+)\s+"[^"]*"\s+BOT') | ForEach-Object { $_.Groups[1].Value })
}
# One line per reading, so the ten re-equips read as a table: provider entity,
# private providers, attributes on the provider, max health, the max-ammo
# multiplier and the reserve ammo of the weapon in hand.
function Snap($label, $id) {
  $text = Rcon "sm_ap_buff_debug #$id"
  $field = { param($pattern) $m = [regex]::Match($text, $pattern); if ($m.Success) { $m.Groups[1].Value } else { '?' } }
  Say ("SNAP {0,-22} bot={1} provider={2} private-providers={3} provider-attributes={4} health={9} max-health={5} max-ammo-multiplier={6} reserve-ammo={7} active={8}" -f `
    $label, $id, (& $field 'provider=(\d+)'), (& $field 'private-providers=(\d+)'), (& $field 'provider-attributes=(-?\d+)'),
    (& $field 'max-health=(-?\d+)'), (& $field 'max-ammo-multiplier=(-?[\d.]+)'), (& $field 'reserve-ammo=(-?\d+)'), (& $field 'active: ent=\d+ class=(\w+)'), (& $field '\[AP debug\] health=(-?\d+)'))
  return $text
}
# A bot that is alive and holds a weapon with a reserve to measure.
function Ammo-Bot($except) {
  foreach ($id in Bot-Ids) {
    if ($id -eq $except) { continue }
    $text = Rcon "sm_ap_buff_debug #$id"
    if ($text -match 'active: ent=\d+' -and $text -match 'reserve-ammo=([1-9]\d*)') { return $id }
  }
}

$null = Wait-For 'the plugin to hold its unlock set' 60 { (Rcon 'sm_ap_status') -match 'held' }
Start-Sleep 10
Rcon 'tf2ap_buffs_for_defender_bots 1' | Out-Null
Rcon 'tf2ap_loadout_for_bots 1' | Out-Null
Rcon 'tf_bot_add 1 red heavy' | Out-Null
$bot = Wait-For 'an alive bot holding an ammo weapon' 60 { Ammo-Bot $null }
if (-not $bot) { exit 1 }
Say "target bot $bot"

function Rebuilds($label) {
  foreach ($line in ((Rcon "sm_ap_buff_rebuild #$bot 10") -split "`n" | Where-Object { $_ -match '\[AP rebuild\]' })) {
    Say "$label $($line.Trim())"
  }
}
function Phase($label, $keep) {
  Rcon "tf2ap_buff_keep_vitals $keep" | Out-Null
  Rcon "sm_ap_loadout_set #$bot primary own" | Out-Null
  Start-Sleep 3
  Say "=== PHASE $label (tf2ap_buff_keep_vitals $keep)"
  foreach ($line in ((Rcon "sm_ap_buff_rebuild #$bot 1 fresh") -split "`n" | Where-Object { $_ -match '\[AP rebuild\]' })) {
    Say "$label clean $($line.Trim())"
  }
  Rcon "sm_ap_buff_give #$bot max-ammo 1" | Out-Null
  Rcon "sm_ap_buff_give #$bot max-health 1" | Out-Null
  $null = Snap "$label after buffs" $bot
  Rebuilds $label
  Start-Sleep 2
  $null = Snap "$label after ten" $bot
}

Phase 'A' 0
Phase 'C' 1
exit 0
