#!/bin/bash
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
#
# The eip=1 faults return under a call through CTFPlayer's vtable +0x1ec, from
# the function at server+0x516480. What sits in that slot, and near it?
v=derived/win-vtables/CTFPlayer.txt
echo "== windows CTFPlayer +0x1d8..+0x200"; awk '/^\/\/ vtable/{n++} n==1' "$v" | grep -E '^\+0x0(1d[89a-f]|1e[0-9a-f]|1f[0-9a-f]|200):'
a=$(awk '/^\/\/ vtable/{n++} n==1' "$v" | grep '^+0x01ec:' | awk '{print $2}')
echo "== slot +0x1ec holds $a; matches.json entries at that address"
python3 - "$a" <<'PY'
import json, sys
va = int(sys.argv[1], 16); rva = va - 0x10000000
for sym, m in json.load(open("derived/matches.json")).items():
    if m.get("rva") == rva: print(sym, m.get("via"))
PY
