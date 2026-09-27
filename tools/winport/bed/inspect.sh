#!/bin/bash
# CBasePlayer::CommitSuicide's two overloads: the Windows slots around 453 in
# CBasePlayer and CTFPlayer with each body's pop and head, the Linux slots
# around the same place by name, and the Linux bodies of both overloads.
python3 - <<'PY'
import re, capstone, pefile
from elftools.elf.elffile import ELFFile
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
pe = pefile.PE("game-windows/tf/bin/server.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = text.get_data(); tv = text.VirtualAddress
def wdis(rva, n=60):
    out = []
    for i in md.disasm(code[rva-tv:rva-tv+2000], base + rva):
        out.append(f"    {i.address-base:#x}  {i.mnemonic} {i.op_str}")
        if i.mnemonic == "ret" or len(out) >= n: break
    return out
def wpop(rva):
    for k, i in enumerate(md.disasm(code[rva-tv:rva-tv+4000], rva)):
        if i.mnemonic == "ret": return i.op_str or "0"
        if k > 600: return "?"
def rows(path):
    out = []
    for l in open(path):
        m = re.match(r"\s*\+(0x[0-9a-f]+):\s+(0x[0-9a-f]+|[0-9a-f]+)\s*(.*)", l)
        if m: out.append((int(m.group(1), 16) // 4, int(m.group(2), 16), m.group(3).strip()))
        elif out: break
    return out
for cls in ("CBasePlayer", "CBaseMultiplayerPlayer", "CTFPlayer"):
    print(f"== windows {cls}")
    for idx, va, _ in rows(f"derived/win-vtables/{cls}.txt"):
        if 446 <= idx <= 460:
            rva = va - base
            head = "; ".join(x.split("  ", 1)[1] for x in wdis(rva, 6))
            print(f"  [{idx}] {rva:#x} ret {wpop(rva)}  {head}")
    print(f"== linux {cls}")
    for idx, va, name in rows(f"derived/linux-vtables/{cls}.txt"):
        if 436 <= idx <= 452: print(f"  [{idx}] {va:#x} {name}")
for rva in (0x2df600,):
    print(f"== windows body {rva:#x}")
    print("\n".join(wdis(rva, 120)))
elf = ELFFile(open("game-linux/tf/bin/server_srv.so", "rb"))
lt = elf.get_section_by_name(".text"); lcode = lt.data(); lva = lt["sh_addr"]
syms = {s.name: (s["st_value"], s["st_size"]) for s in elf.get_section_by_name(".symtab").iter_symbols() if s["st_info"]["type"] == "STT_FUNC"}
for name in ("_ZN11CBasePlayer13CommitSuicideEbb", "_ZN11CBasePlayer13CommitSuicideERK6Vectorbb", "_ZN9CTFPlayer13CommitSuicideEbb", "_ZN9CTFPlayer13CommitSuicideERK6Vectorbb"):
    if name not in syms: print(f"== linux {name} absent"); continue
    a, n = syms[name]
    print(f"== linux {name} at {a:#x} size {n}")
    for k, i in enumerate(md.disasm(lcode[a-lva:a-lva+n], a)):
        if k < 70: print(f"    {i.address:#x}  {i.mnemonic} {i.op_str}")
PY
