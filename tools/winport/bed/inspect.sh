#!/bin/bash
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
so=game-linux/tf/bin/server_srv.so
for s in _ZNK17CAttributeManager13IsProvidingToEP11CBaseEntity _ZN11CBaseEntity13GetDataObjectEi _ZN13CTFWeaponBase19StartEffectBarRegenEv; do
  echo "== linux $s"
  objdump -d --no-show-raw-insn -M intel --disassemble="$s" "$so" | sed -n '/>:$/,$p' | head -50
done
