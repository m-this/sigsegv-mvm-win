#!/bin/bash
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
so=game-linux/tf/bin/server_srv.so
for s in _ZN20CTFObjectiveResource36DecrementMannVsMachineWaveClassCountE8string_tj _ZN19CWaveSpawnPopulator25GetCurrencyAmountPerDeathEv _ZN11CBaseEntity11SetMoveTypeE10MoveType_t13MoveCollide_t; do
  echo "== linux $s"
  objdump -d --no-show-raw-insn -M intel --disassemble="$s" "$so" | sed -n '/>:$/,$p' | head -40
done
