#!/bin/bash
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
#
# Two virtuals the sweep reaches with no Windows address: where do they sit?
primary() { awk '/^\/\/ vtable/{n++} n==1' "$1"; }
for pair in "CTFBaseBoss GetCurrencyValue" "CTFTankBoss GetCurrencyValue" "CBaseCombatWeapon SetSubType"; do
  set -- $pair
  l=derived/linux-vtables/$1.txt; w=derived/win-vtables/$1.txt
  n=$(primary "$l" | grep -n "::$2(" | head -1 | cut -d: -f1)
  echo "== $1::$2, linux row $n"
  [ -n "$n" ] && primary "$l" | sed -n "$((n-4)),$((n+4))p"
  echo "-- windows rows $((n-6))..$((n+2))"
  [ -n "$n" ] && primary "$w" | sed -n "$((n-6)),$((n+2))p"
done
