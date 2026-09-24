#!/bin/sh
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
#
# The table's CTFPlayer::Spawn (0x50d380) and RegenThink (0x508e30) are string
# matches that take arguments. Spawn is virtual: where do both sides put it?
v=derived/win-vtables/CTFPlayer.txt
l=derived/linux-vtables/CTFPlayer.txt
echo "== windows CTFPlayer, lines 1-34"; sed -n '1,34p' "$v"
echo "== linux CTFPlayer, lines 1-34"; sed -n '1,34p' "$l"
echo "== windows lines holding the suspects"; grep -n '50d380\|508e30\|4f3530\|4f3500' "$v"
echo "== matches.json and vtable-index entries for Spawn"; grep -n '_ZN9CTFPlayer5SpawnEv\|_ZN9CTFPlayer10RegenThinkEv' -A4 derived/matches.json | head -20
grep -n 'CTFPlayer::Spawn\|CTFPlayer::RegenThink' tools/winport/knownvtidx.generated.txt derived/*.txt 2>/dev/null | head
