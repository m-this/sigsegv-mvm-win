#!/bin/bash
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
#
# The Linux bodies of the functions the sweep reaches unresolved.
so=game-linux/tf/bin/server_srv.so
for s in _ZN14CBaseAnimating10LookupBoneEPKc _ZNK12CTFGameRules15DropSpellPickupERK6Vectori \
         _Z22GetLoadoutPositionName19loadout_positions_t _Z22PrecacheParticleSystemPKc; do
  echo "== linux $s"
  objdump -d --no-show-raw-insn -M intel --disassemble="$s" "$so" | sed -n '/>:$/,$p' | head -60
done
