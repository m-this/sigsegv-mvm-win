#!/bin/bash
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
so=game-linux/bin/soundemittersystem_srv.so
for s in _ZN23CSoundEmitterSystemBase17AddSoundsFromFileEPKcbbb; do
  echo "== linux $s"
  objdump -d --no-show-raw-insn -M intel --disassemble="$s" "$so" | sed -n '/>:$/,$p' | grep -n 'call\|ret\|push   0x' | head -60
done
