#!/bin/sh
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
#
# The plugin's DispenseAmmo(CTFPlayer*) matched nothing. It is virtual: where do
# both sides put it in the two dispensers' vtables?
for c in CObjectDispenser CRobotDispenser; do
  v=derived/win-vtables/$c.txt
  l=derived/linux-vtables/$c.txt
  echo "== linux $c, DispenseAmmo"; grep -n 'DispenseAmmo' "$l"
  n=$(grep -n 'DispenseAmmo' "$l" | head -1 | cut -d: -f1)
  echo "== linux $c, lines around it"; [ -n "$n" ] && sed -n "$((n-6)),$((n+6))p" "$l"
  echo "== windows $c, lines $((n-10))-$((n+6))"; [ -n "$n" ] && sed -n "$((n-10)),$((n+6))p" "$v"
  echo "== windows $c, head"; sed -n '1,4p' "$v"; wc -l "$v" "$l"
done
grep -n 'DispenseAmmo' derived/matchvtables.log derived/matchfuncs.log | head
