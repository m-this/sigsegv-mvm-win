#!/bin/bash
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
so=game-linux/tf/bin/server_srv.so
for s in _ZN11CBaseEntity12SetNextThinkEfPKc _ZN17CBaseEntityOutput16ParseEventActionEPKc _ZN6CTFBot10ChangeTeamEibbb _ZN6CTFBot6HasTagEPKc; do
  echo "== linux $s"
  objdump -d --no-show-raw-insn -M intel --disassemble="$s" "$so" | sed -n '/>:$/,$p' | head -60
done
