#!/bin/bash
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
#
# The Linux bodies of the functions the sweep reaches unresolved, to read
# beside the Windows candidates or to write where MSVC inlined them.
so=game-linux/tf/bin/server_srv.so
for s in _ZN18CPopulationManager14CollectMvMBotsEP10CUtlVectorIP9CTFPlayer10CUtlMemoryIS2_iEE \
         _Z37MannVsMachineStats_GetAcquiredCreditsib _ZN18CCollisionProperty8SetSolidE11SolidType_t; do
  echo "== linux $s"
  objdump -d --no-show-raw-insn -M intel -C --disassemble="$s" "$so" | sed -n '/>:$/,$p' | head -120
done
