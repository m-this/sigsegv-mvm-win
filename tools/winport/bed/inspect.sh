#!/bin/bash
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
#
# DispenseAmmo(CTFPlayer*) is Linux slot 0x6a4 in both dispensers, and the
# Windows primary vtables stop at 0x688. Which slots does CRobotDispenser
# override on each side, and what does CObjectDispenser add over CBaseObject?
primary() { awk '/^\/\/ vtable/{n++} n==1 && /^\+0x/' "$1"; }
for side in linux win; do
  echo "== $side: slots where CRobotDispenser differs from CObjectDispenser"
  diff <(primary derived/$side-vtables/CObjectDispenser.txt) <(primary derived/$side-vtables/CRobotDispenser.txt)
  echo "== $side: CObjectDispenser slots past CBaseObject's"
  b=$(primary derived/$side-vtables/CBaseObject.txt | wc -l)
  echo "CBaseObject has $b"
  primary derived/$side-vtables/CObjectDispenser.txt | sed -n "$((b-2)),\$p"
done
