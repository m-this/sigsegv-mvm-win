#!/bin/bash
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
#
# CBaseCombatWeapon::SetSubType is virtual and its neighbours are shared stubs.
# CTFWeaponBuilder overrides it: the Windows slot where the builder's table
# differs from the base weapon's near +0x3b8 is it.
primary() { awk '/^\/\/ vtable/{n++} n==1 && /^\+0x/' "$1"; }
for side in linux win; do
  echo "== $side: CTFWeaponBuilder against CTFWeaponBase, +0x380..+0x3f0"
  diff <(primary derived/$side-vtables/CTFWeaponBase.txt | awk '$1>="+0x0380:" && $1<="+0x03f0:"') \
       <(primary derived/$side-vtables/CTFWeaponBuilder.txt | awk '$1>="+0x0380:" && $1<="+0x03f0:"')
done
