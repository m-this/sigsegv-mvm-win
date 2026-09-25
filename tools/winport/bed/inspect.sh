#!/bin/bash
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
so=game-linux/tf/bin/server_srv.so
for s in _ZN6CTFBot24EquipBestWeaponForThreatEPK12CKnownEntity _ZN7CZombie10SpawnAtPosERK6VectorfiP11CBaseEntityNS_14SkeletonType_tE; do
  echo "== linux $s"
  objdump -d --no-show-raw-insn -M intel --disassemble="$s" "$so" | sed -n '/>:$/,$p' | head -45
done
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
# variant_t::SetOther(void *): opens on `cmp dword ptr [reg+0x10], 0xf; ja`
for x in re.finditer(rb"\x83[\x78-\x7f]\x10\x0f\x77", code):
    print(f"SetOther-shaped cmp at {va + x.start():#x} in {start(va + x.start()):#x}")
# CBaseEntityOutput::ParseEventAction: a 0x1c pool Alloc, then CEventAction's constructor
ctor = m.get("_ZN12CEventActionC1EPKc") or m.get("_ZN12CEventActionC2EPKc")
print("CEventAction ctor", ctor)
for x in re.finditer(rb"\x6a\x1c\x68(....)\xe8", code, re.S):
    at = va + x.start()
    near = code[x.start():x.start() + 48]
    if ctor:
        calls = [va + x.start() + i + 5 + int.from_bytes(near[i+1:i+5], "little", signed=True) for i in range(len(near) - 5) if near[i] == 0xE8]
        if ctor["rva"] not in calls: continue
    print(f"pool alloc of 0x1c at {at:#x} in {start(at):#x}, pool {int.from_bytes(x.group(1), 'little'):#x}")
PY
