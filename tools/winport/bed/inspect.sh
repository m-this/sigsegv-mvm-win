#!/bin/sh
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
#
# eip=1 under UpdateConnectedPlayer, right after a no-argument virtual call on
# the player at vtable +0x1ec (slot 123). The table gives CTFPlayer::Spawn and
# RegenThink, both without arguments, addresses that end ret 4 and ret 8.
v=derived/win-vtables/CTFPlayer.txt
l=derived/linux-vtables/CTFPlayer.txt
echo "== windows CTFPlayer vtable, slots 118-128"; sed -n '1,3p' "$v"; grep -n '' "$v" | sed -n '118,132p'
echo "== linux CTFPlayer vtable: Spawn, RegenThink, and slots 118-128"; grep -n 'Spawn\|RegenThink' "$l" | head; grep -n '' "$l" | sed -n '118,132p'
echo "== where 0x50d380 and 0x508e30 sit in the windows vtables"; grep -rl '50d380\|508e30' derived/win-vtables | head
