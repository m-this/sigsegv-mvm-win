#!/bin/bash
# The Linux bodies of the pairs the overload rule moves in windows.txt.
so=game-linux/tf/bin/server_srv.so
for sym in _ZN20CBaseCombatCharacter11FInViewConeERK6Vector _ZN20CBaseCombatCharacter11FInViewConeEP11CBaseEntity \
           _ZN20CBaseCombatCharacter10RemoveAmmoEii _ZN20CBaseCombatCharacter10RemoveAmmoEiPKc \
           _ZN11CSmokeStack8KeyValueEPKcS1_ _ZN15CAmbientGeneric8KeyValueEPKcS1_; do
  read -r addr size <<< "$(nm -S --defined-only $so | awk -v s=$sym '$4 == s { print $1, $2; exit }')"
  [ -n "$addr" ] || { echo "== $sym: not found"; continue; }
  start=$((16#$addr)); end=$((start + 16#$size))
  echo "== $sym at 0x$addr size 0x$size"
  objdump -d --no-show-raw-insn -M intel --start-address=$start --stop-address=$end $so | tail -n +8 | head -70 | c++filt
done
true
