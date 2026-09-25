#!/bin/bash
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
# CBaseCombatCharacter::Weapon_Detach(CBaseCombatWeapon *): on Linux a loop of
# 0x30 over m_hMyWeapons (+0x788), then the weapon's vtable +0x454 and +0x44c.
# On Windows the fields sit 0x18 lower and the slots 4 lower: functions naming
# +0x760..+0x780, comparing with 0x30, and calling through +0x450 or +0x448.
python3 - <<'PY'
import re, pefile, capstone
pe = pefile.PE("game-windows/tf/bin/server.dll")
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code, va = text.get_data(), text.VirtualAddress
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
starts = [m.end() for m in re.finditer(rb"\xcc\xcc+", code)]
for i in range(len(starts) - 1):
    a, b = starts[i], starts[i + 1]
    if b - a > 2500 or b - a < 60: continue
    body = code[a:b]
    if not re.search(rb"[\x60-\x80]\x07\x00\x00", body): continue
    if not re.search(rb"\x83[\xf8-\xff]\x30", body): continue
    # the loop compares a handle it looked up with the argument
    if not re.search(rb"\x3b[\x40-\x7f]\x08|\x39[\x40-\x7f]\x08", body): continue
    print(f"candidate {va + a:#x} ({b - a} bytes)")
    for k, ins in enumerate(md.disasm(body, base + va + a)):
        print(f"  {ins.address - base:#x}  {ins.mnemonic} {ins.op_str}")
        if k >= 14: break
PY
