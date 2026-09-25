#!/bin/bash
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
#
# The Linux bodies of the functions the sweep reaches unresolved, to write
# where MSVC inlined them.
so=game-linux/tf/bin/server_srv.so
for s in _ZNK9CTFPlayer14GetObjectCountEv _ZN11CTFBaseBoss16GetCurrencyValueEv \
         _ZN5CWave25IsDoneWithNonSupportWavesEv _ZN11CBaseEntity19ClassMatchesComplexEPKc \
         _Z45AllocPooledString_StaticConstantStringPointerPKc _ZN17CBaseCombatWeapon10SetSubTypeEi; do
  echo "== linux $s"
  objdump -d --no-show-raw-insn -M intel --disassemble="$s" "$so" | sed -n '/>:$/,$p' | head -70
done
