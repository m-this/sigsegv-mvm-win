#!/bin/bash
# Weapon_Detach inlined on Windows: sites that load the Detach slot (Linux 277
# less 6, +0x43c) and the HolsterOnDetach slot (275 less 6, +0x434) within a
# few instructions of each other. SetOwner: every function pushing
# 'BaseCombatWeapon_HideThink', whole.
python3 - <<'PY'
import re, capstone, pefile

pe = pefile.PE("game-windows/tf/bin/server.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
sec = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = sec.get_data(); tva = base + sec.VirtualAddress
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

def start_of(at):
    while at > 0 and not (code[at - 1] in (0xCC, 0x90) and code[at - 2] in (0xCC, 0x90)):
        at -= 1
    return at

def show(at, n):
    for count, i in enumerate(md.disasm(code[at:at + 0x1000], tva + at)):
        line = f"  {i.address - base:#x}  {i.mnemonic} {i.op_str}"
        if i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x"):
            line += f"    -> {int(i.op_str, 16) - base:#x}"
        print(line)
        if count + 1 >= n or (i.mnemonic == "int3"):
            break

# mov r32, [r32 + disp32] or call [r32 + disp32], for one displacement.
def through(disp):
    d = disp.to_bytes(4, "little")
    return {m.start() for m in re.finditer(rb"[\x8b\xff][\x80-\xbf]" + re.escape(d), code)}

detach, hod = through(0x43c), through(0x434)
sites = sorted({start_of(a) for a in detach for b in hod if 0 < b - a < 0x30})
print(f"=== {len(sites)} functions loading +0x43c then +0x434")
for s in sites[:6]:
    print(f"--- function 0x{tva + s - base:x}")
    show(s, 160)

data = pe.__data__
off = data.find(b"BaseCombatWeapon_HideThink\0")
ref = (base + pe.get_rva_from_offset(off)).to_bytes(4, "little")
refs = [m.start() for m in re.finditer(b"\x68" + re.escape(ref), code)]
print(f"=== {len(refs)} pushes of 'BaseCombatWeapon_HideThink'")
for s in sorted({start_of(r) for r in refs}):
    print(f"--- function 0x{tva + s - base:x}")
    show(s, 220)
PY
