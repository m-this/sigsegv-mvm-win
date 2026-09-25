#!/bin/bash
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
so=game-linux/tf/bin/server_srv.so
for s in _ZN20CBaseCombatCharacter13AddGlowEffectEv _ZNK9CTFPlayer9GetObjectEi _ZN9CTFPlayer16DoAnimationEventE17PlayerAnimEvent_ti; do
  echo "== linux $s"
  objdump -d --no-show-raw-insn -M intel --disassemble="$s" "$so" | sed -n '/>:$/,$p' | head -40
done
# CTFPlayer::UpdateModel: on Linux SetModel through vtable +0x6c, then +0x580 and
# +0x57c, SetCollisionBounds, and a tail jump to OnNewModel. On Windows one
# destructor fewer: the callers of SetCollisionBounds calling [reg+0x57c] and [reg+0x578].
python3 - <<'PY'
import json, re, pefile
pe = pefile.PE("game-windows/tf/bin/server.dll")
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code, va = text.get_data(), text.VirtualAddress
m = json.load(open("derived/matches.json"))
scb = m["_ZN11CBaseEntity18SetCollisionBoundsERK6VectorS2_"]["rva"]
def start(rva):
    at = rva - va
    while at > 0 and not (code[at - 1] in (0xCC, 0x90) and code[at - 2] in (0xCC, 0x90)):
        at -= 1
    return va + at
seen = set()
for x in re.finditer(rb"\xe8", code):
    src = va + x.start()
    if src + 5 + int.from_bytes(code[x.start()+1:x.start()+5], "little", signed=True) != scb: continue
    f = start(src)
    if f in seen: continue
    seen.add(f)
    body = code[f - va:src - va + 40]
    if re.search(rb"\xff[\x50-\x57\x90-\x97]\x7c\x05\x00\x00", body) and re.search(rb"\xff[\x50-\x57\x90-\x97]\x78\x05\x00\x00", body):
        print(f"UpdateModel candidate {f:#x}, SetCollisionBounds call at {src:#x}, {src - f:#x} in")
PY
