#!/bin/bash
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
so=game-linux/tf/bin/server_srv.so
for s in _ZN15CItemGeneration9SpawnItemEiRK6VectorRK6QAngleiiPKc; do
  echo "== linux $s"
  objdump -d --no-show-raw-insn -M intel --disassemble="$s" "$so" | sed -n '/>:$/,$p' | head -90
done
so=game-linux/bin/soundemittersystem_srv.so
for s in _ZN23CSoundEmitterSystemBase17AddSoundsFromFileEPKcbbb; do
  echo "== linux $s"
  objdump -d --no-show-raw-insn -M intel --disassemble="$s" "$so" | sed -n '/>:$/,$p' | head -60
  objdump -s -j .rodata "$so" | grep -i -m5 'precache\|manifest\|soundscript' || true
done
