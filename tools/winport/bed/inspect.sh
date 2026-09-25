#!/bin/bash
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
python3 - <<'PY'
import json, re, pefile
pe = pefile.PE("game-windows/tf/bin/server.dll")
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code, va = text.get_data(), text.VirtualAddress
m = json.load(open("derived/matches.json"))
def start(rva):
    at = rva - va
    while at > 0 and not (code[at - 1] in (0xCC, 0x90) and code[at - 2] in (0xCC, 0x90)):
        at -= 1
    return va + at
def callers(rva):
    out = set()
    for x in re.finditer(rb"\xe8", code):
        src = va + x.start()
        if src + 5 + int.from_bytes(code[x.start()+1:x.start()+5], "little", signed=True) == rva:
            out.add(start(src))
    return out
# CTFPlayer::UpdateModel: SetModel(GetModelName()), SetCollisionBounds, then OnNewModel
sets = []
for sym in ["_ZNK20CTFPlayerClassShared12GetModelNameEv", "_ZN11CBaseEntity18SetCollisionBoundsERK6VectorS2_", "_ZN21CMultiPlayerAnimState10OnNewModelEv"]:
    e = m.get(sym)
    print(sym, e)
    if e: sets.append(callers(e["rva"]))
if sets:
    common = set.intersection(*sets) if len(sets) > 1 else sets[0]
    print("UpdateModel candidates, calling all of them:", sorted(hex(x) for x in common))
    if len(sets) > 1:
        print("calling the first two:", sorted(hex(x) for x in sets[0] & sets[1]))
# NextBotPlayer<CTFPlayer>::Release*Button, any encoding: an and on [ecx+X] then a store of -1.0f to [ecx+Y], within a few bytes
for x in re.finditer(rb"\x00\x00\x80\xbf", code):
    lo = max(0, x.start() - 20)
    window = code[lo:x.start() + 6]
    if (b"\x83\xa1" in window or b"\x81\xa1" in window or b"\x83\x61" in window or b"\x81\x61" in window) and b"\xc7\x81" in window or b"\xc7\x41" in window and (b"\x83\x61" in window or b"\x83\xa1" in window):
        if window.find(b"\xc3", window.find(b"\x00\x00\x80\xbf")) != -1:
            print(f"release-shaped at rva {va + lo:#x}: {window.hex(' ')}")
PY
# The vtable slots of CEconEntity::GiveTo and CTFBaseBoss::UpdateCollisionBounds, both empty bodies
ls derived/linux-vtables | head -3; ls derived/win-vtables | head -3
for c in CEconEntity CTFBaseBoss; do
  f=$(ls derived/linux-vtables | grep -i "^${c}[._]" | head -1); echo "== linux $c ($f)"; grep -n -i "GiveTo\|UpdateCollisionBounds" "derived/linux-vtables/$f" | head; 
  g=$(ls derived/win-vtables | grep -i "${c}@@\|^${c}[._]" | head -1); echo "== windows $c ($g)"; head -3 "derived/win-vtables/$g"
done
