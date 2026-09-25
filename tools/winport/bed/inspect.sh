#!/bin/bash
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
objdump -d --no-show-raw-insn -M intel --disassemble=_ZN20CBaseCombatCharacter13Weapon_DetachEP17CBaseCombatWeapon game-linux/tf/bin/server_srv.so | sed -n '/>:$/,$p' | head -40
python3 - <<'PY'
import json, re, pefile, capstone
pe = pefile.PE("game-windows/tf/bin/server.dll")
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code, va = text.get_data(), text.VirtualAddress
data = pe.__data__
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
def start(rva):
    at = rva - va
    while at > 0 and not (code[at - 1] in (0xCC, 0x90) and code[at - 2] in (0xCC, 0x90)):
        at -= 1
    return va + at
def show(f, n=40):
    out = []
    for i, ins in enumerate(md.disasm(code[f - va:f - va + 600], base + f)):
        out.append(f"  {ins.address - base:#x}  {ins.mnemonic} {ins.op_str}")
        if ins.mnemonic == "ret" or i >= n: break
    print("\n".join(out))
# CZombie::SpawnAtPos: pushes "tf_zombie" then -1 for CreateEntityByName
for m in re.finditer(rb"tf_zombie\x00", data):
    sva = base + pe.get_rva_from_offset(m.start())
    for x in re.finditer(re.escape(b"\x68" + sva.to_bytes(4, "little")), code):
        f = start(va + x.start())
        print(f"push 'tf_zombie' ({sva:#x}) at {va + x.start():#x} in {f:#x}")
        show(f, 30)
# CBaseEntityOutput::ParseEventAction: CEventAction's constructor called right after a pool Alloc of 0x1c
ctor = 0x224e40
for x in re.finditer(rb"\xe8", code):
    src = va + x.start()
    if src + 5 + int.from_bytes(code[x.start()+1:x.start()+5], "little", signed=True) != ctor: continue
    f = start(src)
    if src - f < 0x40:
        print(f"CEventAction ctor called at {src:#x}, {src - f:#x} into {f:#x}")
        show(f, 30)
PY
