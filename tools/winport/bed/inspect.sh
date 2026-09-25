#!/bin/bash
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
# CBaseCombatCharacter::Weapon_Detach(CBaseCombatWeapon *): walks the 48
# m_hMyWeapons for the argument, then SetOwner(NULL) on it. The Windows
# functions that call SetOwner with a pushed 0 and compare a counter with 0x30.
python3 - <<'PY'
import json, re, pefile, capstone
pe = pefile.PE("game-windows/tf/bin/server.dll")
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code, va = text.get_data(), text.VirtualAddress
m = json.load(open("derived/matches.json"))
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
def start(rva):
    at = rva - va
    while at > 0 and not (code[at - 1] in (0xCC, 0x90) and code[at - 2] in (0xCC, 0x90)):
        at -= 1
    return va + at
so = m.get("_ZN17CBaseCombatWeapon8SetOwnerEP20CBaseCombatCharacter")
print("SetOwner", so)
if so:
    seen = set()
    for x in re.finditer(rb"\x6a\x00", code):
        at = x.start() + 2
        for k in range(at, min(at + 8, len(code) - 5)):
            if code[k] == 0xE8 and va + k + 5 + int.from_bytes(code[k+1:k+5], "little", signed=True) == so["rva"]:
                f = start(va + k)
                body = code[f - va:va + k - va]
                if f not in seen and (b"\x83\xff\x30" in body or b"\x83\xfe\x30" in body or b"\x83\xf8\x30" in body or b"\x83\xf9\x30" in body or b"\x83\xfb\x30" in body):
                    seen.add(f)
                    print(f"candidate {f:#x}, SetOwner(0) at {va + k:#x}")
                    out = []
                    for i, ins in enumerate(md.disasm(code[f - va:f - va + 400], base + f)):
                        out.append(f"  {ins.address - base:#x}  {ins.mnemonic} {ins.op_str}")
                        if i >= 45: break
                    print("\n".join(out))
PY
