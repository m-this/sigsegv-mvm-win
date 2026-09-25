#!/bin/bash
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
#
# The Linux bodies of the functions the sweep reaches unresolved.
so=game-linux/tf/bin/server_srv.so
for s in _ZN18CPopulationManager14GetCurrentWaveEv _ZNK9CTFPlayer19GetDesiredHeadScaleEv; do
  echo "== linux $s"
  objdump -d --no-show-raw-insn -M intel --disassemble="$s" "$so" | sed -n '/>:$/,$p' | head -60
done
