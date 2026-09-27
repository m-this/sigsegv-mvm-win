#!/bin/bash
# CTFGCServerSystem::PreClientUpdate: the strings and globals its two bodies use,
# and the rest of the Windows body.
python3 - <<'PY'
import capstone, pefile, bisect
from elftools.elf.elffile import ELFFile
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

elf = ELFFile(open("game-linux/tf/bin/server_srv.so", "rb"))
objs = {}
for s in elf.get_section_by_name(".symtab").iter_symbols():
    if s["st_value"] and s["st_info"]["type"] in ("STT_OBJECT", "STT_FUNC"):
        objs.setdefault(s["st_value"], (s.name, s["st_size"]))
starts = sorted(objs)
def lsym(a):
    i = bisect.bisect_right(starts, a) - 1
    if i < 0: return "?"
    n, sz = objs[starts[i]]
    return n + (f"+{a - starts[i]:#x}" if a != starts[i] else "")
def lstr(a):
    for sec in elf.iter_sections():
        if sec["sh_type"] != "SHT_NOBITS" and sec["sh_addr"] <= a < sec["sh_addr"] + sec["sh_size"]:
            d = sec.data(); o = a - sec["sh_addr"]; e = d.find(b"\0", o)
            return repr(d[o:e][:120].decode(errors="replace"))
    return "(not in a file section)"
print("=== linux strings")
for a in [0x13850d0, 0x13850eb, 0x13850f1, 0x138505a, 0x1386b0c, 0x1386ae4, 0x1386ab8, 0x1386a80, 0x1386a44]:
    print(f"  {a:#x} {lstr(a)}")
print("=== linux globals")
for a in [0x196f000, 0x196f01c, 0x190963c, 0x196f3e0, 0x196f3d0, 0x196f3c8, 0x196f3d8, 0x196f3e8, 0x17f53b0, 0x17f63fc, 0x17f5204]:
    print(f"  {a:#x} {lsym(a)}")

pe = pefile.PE("game-windows/tf/bin/server.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
def wstr(va):
    try:
        b = pe.get_data(va - base, 160); return repr(b.split(b"\0")[0].decode(errors="replace"))
    except Exception as e:
        return f"({e})"
print("=== windows strings")
for va in [0x108b5950, 0x108b5968, 0x108b59a0, 0x108b58f8, 0x108b5934, 0x108b5a38, 0x108b5a68]:
    print(f"  {va:#x} {wstr(va)}")
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = text.get_data(); tv = text.VirtualAddress
print("== windows 0x5ca966 on")
for n, i in enumerate(md.disasm(code[0x5ca966 - tv:0x5ca966 - tv + 2000], base + 0x5ca966)):
    extra = ""
    if i.mnemonic == "push" and i.op_str.startswith("0x108"):
        extra = "    " + wstr(int(i.op_str, 16))
    print(f"  {i.address - base:#x}  {i.mnemonic} {i.op_str}{extra}")
    if i.mnemonic == "int3" or n > 200: break
PY
