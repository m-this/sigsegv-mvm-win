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
def refs_to_string(text):
    return sorted(site for site, t in wstr_sites.items() if t == text)

wstr_sites = {}
for site in win.relocs:
    if win.in_text(site):
        continue
    try:
        v = win.read_u32(site)
    except Exception:
        continue
    raw = wread(v, 96).split(b"\0")[0]
    if all(32 <= c < 127 for c in raw) and win.in_text(v) is False:
        wstr_sites[site] = raw.decode("latin-1")

print("==== A. the class name tables")
for text in ["heavyweapons", "demoman", "Heavy", "heavy"]:
    for site in refs_to_string(text):
        row = [wstr_sites.get(site + 4 * i, "-") for i in range(-6, 8)]
        print(f"   {text!r} at {site - B:#x}: {row}")
for text in ["heavyweapons", "demoman"]:
    hits = wfind(text.encode() + b"\0")
    print(f"   string {text!r}: {[(n, hex(r)) for n, r in hits][:10]}")
print("   g_szLoadoutStrings at 0x9c1768:", [wstr_sites.get(B + 0x9c1768 + 4 * i, "-") for i in range(19)])
print("   raw", wread(B + 0x9c1768, 19 * 4).hex())

print("==== D. code naming a vtable")
for cls in ["IPredictionSystem", "CRecipientFilter"]:
    try:
        rows = open(f"derived/win-vtables/{cls}.txt").read().splitlines()
    except OSError:
        print(f"   {cls}: no table")
        continue
    heads = [r for r in rows if r.startswith("// vtable")]
    print(f"   {cls}: {heads}")
    for h in heads:
        vt = int(h.split()[3], 16)
        for s in text_refs(vt)[:12]:
            f, text = insn_at(s)
            print(f"      vtable {vt - B:#x} named in {f - B:#x}  {text}")
import os
print("   tables:", [f for f in os.listdir("derived/win-vtables") if "redict" in f])

print("==== G. Linux bodies")
lbody("_GLOBAL__sub_I__ZN16CRecipientFilterC2Ev", 40)
lbody("_ZN16CRecipientFilter18UsePredictionRulesEv", 40)
lbody("_GLOBAL__sub_I_sv_unlag", 60)
PY
