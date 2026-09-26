#!/bin/bash
# Where the unresolved globals live on Windows, second pass: data found by its
# content, pointer tables by the strings they point at, and a few bodies read
# around one reference.
cd "$(dirname "$0")/../../.." || exit 1
python3 - <<'PY'
import bisect, struct, sys
sys.path.insert(0, "tools/winport")
import capstone
import matchfuncs as mf
from elftools.elf.sections import SymbolTableSection

linux = mf.Linux("game-linux/tf/bin/server_srv.so")
win = mf.Windows("game-windows/tf/bin/server.dll")
B = win.base
cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

sym = {}
for section in linux.elf.iter_sections():
    if isinstance(section, SymbolTableSection):
        for s in section.iter_symbols():
            if s["st_value"] and s["st_shndx"] != "SHN_UNDEF":
                sym.setdefault(s.name, (s["st_value"], s["st_size"]))

def lbytes(addr, size):
    for s in linux.elf.iter_sections():
        if s["sh_addr"] <= addr < s["sh_addr"] + s["sh_size"] and s["sh_type"] != "SHT_NOBITS":
            return s.data()[addr - s["sh_addr"]:addr - s["sh_addr"] + size]
    return None

def lu32(addr):
    return struct.unpack("<I", lbytes(addr, 4))[0]

wsecs = [(s.Name.rstrip(b"\0").decode(), B + s.VirtualAddress, s.get_data()) for s in win.pe.sections]

def wfind(needle):
    out = []
    for name, va, data in wsecs:
        at = data.find(needle)
        while at >= 0:
            out.append((name, va + at - B))
            at = data.find(needle, at + 1)
    return out

def wread(va, n):
    for name, sva, data in wsecs:
        if sva <= va < sva + len(data):
            return data[va - sva:va - sva + n]
    return b"\0" * n

def text_refs(value):
    code = win.text_bytes
    out, at = [], code.find(struct.pack("<I", value))
    while at >= 0:
        out.append(win.text_start + at)
        at = code.find(struct.pack("<I", value), at + 1)
    return out

def insn_at(site):
    f = win.function_of(site) or site - 0x40
    for i in cs.disasm(win.text_bytes[f - win.text_start:site + 16 - win.text_start], f):
        if i.address <= site < i.address + i.size:
            return f, f"{i.address - B:#x}: {i.mnemonic} {i.op_str}"
    return f, "?"

def lbody(name, limit=60):
    a = linux.by_name.get(name)
    if a is None:
        print(f"   {name}: none")
        return
    size = linux.functions[a][1]
    print(f"   -- {name} {a:#x} size {size:#x}")
    for n, i in enumerate(cs.disasm(linux.text_bytes[a - linux.text["sh_addr"]:a + size - linux.text["sh_addr"]], a)):
        if n >= limit:
            break
        print(f"      {i.address:#x}: {i.mnemonic} {i.op_str}")
print("==== IPredictionSystem objects and who reads their fields")
for obj in [0x9857dc, 0x9a97a8, 0x9c4070]:
    for off in (0, 4, 8, 0xc, 0x10):
        for site in text_refs(B + obj + off)[:10]:
            f, text = insn_at(site)
            print(f"   {obj:#x}+{off:#x} in {f - B:#x}  {text}")
PY
