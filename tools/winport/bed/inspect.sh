#!/bin/bash
# Weapon_Detach is inlined on Windows. Its Linux body with its calls named; the
# Linux slots it calls through; the Windows inlined copies, found by the
# HolsterOnDetach slot (Linux 275 less 6) called beside the Holster slot; and
# SetOwner's candidate, the function referencing 'BaseCombatWeapon_HideThink'.
python3 - <<'PY'
import re, subprocess, capstone, pefile
from elftools.elf.elffile import ELFFile

so = "game-linux/tf/bin/server_srv.so"
elf = ELFFile(open(so, "rb"))
syms = {}; names = {}
for sec in elf.iter_sections():
    if sec.header.sh_type in ("SHT_SYMTAB", "SHT_DYNSYM"):
        for s in sec.iter_symbols():
            if s["st_info"]["type"] == "STT_FUNC" and s["st_value"]:
                syms[s.name] = (s["st_value"], s["st_size"])
                names.setdefault(s["st_value"], s.name)
text = elf.get_section_by_name(".text")
tdata = text.data(); taddr = text["sh_addr"]
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

def demangle(n):
    return subprocess.run(["c++filt", n], capture_output=True, text=True).stdout.strip()

def linux(sym):
    va, size = syms[sym]
    print(f"=== linux {demangle(sym)}  0x{va:x} size {size}")
    for i in md.disasm(tdata[va - taddr:va - taddr + size], va):
        line = f"  {i.address:#x}  {i.mnemonic} {i.op_str}"
        if i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x"):
            t = int(i.op_str, 16)
            if t in names: line += f"    -> {demangle(names[t])}"
        print(line)

linux("_ZN20CBaseCombatCharacter13Weapon_DetachEP17CBaseCombatWeapon")

def rows(path):
    out = []
    for l in open(path):
        if l.startswith("// vtable") and "offset 0x0000" not in l: break
        m = re.match(r'\+0x([0-9a-f]+):\s+([0-9a-f]+)\s*(.*)', l)
        if m: out.append((int(m.group(2), 16), m.group(3).strip()))
    return out

pe = pefile.PE("game-windows/tf/bin/server.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
sec = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = sec.get_data(); tva = base + sec.VirtualAddress

def head(va, n=6):
    return "; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in list(md.disasm(code[va - tva:va - tva + 0x40], va))[:n])

lin = rows("derived/linux-vtables/CTFWeaponBase.txt"); win = rows("derived/win-vtables/CTFWeaponBase.txt")
for s in range(275, 300):
    print(f"  linux {s}: {lin[s][1]}")
for s in range(266, 292):
    print(f"  windows {s}: 0x{win[s][0] - base:x}  {head(win[s][0])}")

# call dword ptr [reg + 0x434], Windows HolsterOnDetach if the shift holds:
# each site with what comes before it.
hits = [m.start() for m in re.finditer(rb"\xff[\x90-\x93\x95-\x97]\x34\x04\x00\x00", code)]
print(f"=== {len(hits)} calls through +0x434")
for at in hits[:8]:
    va = tva + at
    print(f"--- site 0x{va - base:x}")
    for i in md.disasm(code[at - 0x70:at + 0x50], va - 0x70):
        line = f"  {i.address - base:#x}  {i.mnemonic} {i.op_str}"
        if i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x"):
            line += f"    -> {int(i.op_str, 16) - base:#x}"
        print(line)
PY
