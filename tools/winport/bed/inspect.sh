#!/bin/bash
# Weapon_Detach is inlined on Windows. Its Linux body, and the bodies of what it
# calls (CBaseCombatWeapon's Detach, HolsterOnDetach, Holster, SetOwner), with
# every call named; then CTFWeaponBase's slots for those virtuals on both sides.
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
    print(f"=== linux {demangle(sym)}  {sym}  0x{va:x} size {size}")
    for i in md.disasm(tdata[va - taddr:va - taddr + size], va):
        line = f"  {i.address:#x}  {i.mnemonic} {i.op_str}"
        if i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x"):
            t = int(i.op_str, 16)
            if t in names: line += f"    -> {demangle(names[t])}"
        print(line)

want = [s for s in syms if re.search(r"(Weapon_Detach|6DetachEv|15HolsterOnDetachEv|8SetOwnerEP20CBaseCombatCharacter)$", s)]
want += ["_ZN17CBaseCombatWeapon7HolsterEPS_"]
for s in sorted(set(want)):
    if s in syms: linux(s)

# Who calls Weapon_Detach on Linux: a virtual among them gives a Windows body
# with the inlined loop to read the slots off.
wd = syms["_ZN20CBaseCombatCharacter13Weapon_DetachEP17CBaseCombatWeapon"][0]
callers = set()
for m in re.finditer(rb"\xe8", tdata):
    at = taddr + m.start()
    if at + 5 + int.from_bytes(tdata[m.start() + 1:m.start() + 5], "little", signed=True) == wd:
        f = max((v for v in names if v <= at and at < v + max(syms.get(names[v], (0, 0))[1], 1)), default=None)
        callers.add(demangle(names[f]) if f else hex(at))
print("=== linux callers of Weapon_Detach:", "; ".join(sorted(callers)))

pe = pefile.PE("game-windows/tf/bin/server.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
sec = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = sec.get_data(); tva = base + sec.VirtualAddress

def rows(path, win):
    out = []
    for l in open(path):
        if l.startswith("// vtable") and "offset 0x0000" not in l: break
        m = re.match(r'\+0x([0-9a-f]+):\s+([0-9a-f]+)\s*(.*)', l)
        if m: out.append((int(m.group(2), 16), m.group(3).strip()))
    return out

def head(va, n=6):
    return "; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in list(md.disasm(code[va - tva:va - tva + 0x40], va))[:n])

for cls in ("CTFWeaponBase", "CTFWeaponBaseGun"):
    lin = rows(f"derived/linux-vtables/{cls}.txt", False); win = rows(f"derived/win-vtables/{cls}.txt", True)
    print(f"=== {cls}: linux {len(lin)} slots, windows {len(win)}")
    hol = [i for i, (a, n) in enumerate(win) if a - base == 0x6365f0]
    print(f"  windows slots holding CTFWeaponBase::Holster 0x6365f0: {hol}")
    for i, (a, n) in enumerate(lin):
        if re.search(r"::(Detach|HolsterOnDetach|Holster|CanHolster|Deploy|SetOwner)\(", n):
            print(f"  linux {i}: {n}")
    for s in range(240, 275):
        print(f"  linux {s}: {lin[s][1]}")
    for s in range(230, 270):
        print(f"  windows {s}: 0x{win[s][0] - base:x}  {head(win[s][0])}")
PY
