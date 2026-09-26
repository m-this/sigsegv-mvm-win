#!/bin/bash
# Virtuals the bed reached with no Windows slot: each one's Linux slot, the
# slots the tables already pair for its class (the shift near it), and the
# Windows rows around where the shift puts it.
for pair in "CBasePlayer Weapon_ShootPosition" "CEconEntity ReapplyProvision" \
            "CTFWeaponBaseGun GetProjectileSpeed" "CTFWeaponBaseGun GetWeaponProjectileType" \
            "CBaseEntity GetDataObject" "CBaseObject InitializeMapPlacedObject"; do
  set -- $pair; cls=$1; fn=$2
  echo "=== $cls::$fn"
  lf=$(ls derived/linux-vtables | grep -x "$cls.txt" | head -1)
  wf=$(ls derived/win-vtables | grep -x "$cls.txt" | head -1)
  echo "files: linux=$lf windows=$wf"
  [ -n "$lf" ] && grep -n "$fn" "derived/linux-vtables/$lf" | head -3
  grep -A4 "^\"$cls::" tools/winport/knownvtidx.generated.txt | grep -E '^"|idx|linux' | paste - - - | head -40
done
echo "=== formats"
head -5 derived/linux-vtables/CBasePlayer.txt; head -5 derived/win-vtables/CBasePlayer.txt
