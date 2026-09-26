#!/bin/bash
# ~CBaseEntity on Windows: the scalar deleting destructors in slot 0 of
# CBaseEntity and two derived tables, the body they call, and the Linux D2
# body with its callees named.
python3 - <<'PY'
import re, struct, capstone, pefile
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
pe = pefile.PE("game-windows/tf/bin/server.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = text.get_data(); tva = base + text.VirtualAddress
def rows(path):
    out = []
    for l in open(path):
        if l.startswith("// vtable") and "offset 0x0000" not in l: break
        m = re.match(r'\+0x([0-9a-f]+):\s+([0-9a-f]+)\s*(.*)', l)
        if m: out.append((int(m.group(2), 16), m.group(3).strip()))
    return out
def wdis(va, n, title):
    print(f"== windows {title} 0x{va - base:x}")
    for c, i in enumerate(md.disasm(code[va - tva:va - tva + 0x1000], va)):
        extra = ""
        if i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x"):
            extra = f"    -> 0x{int(i.op_str, 16) - base:x}"
        print(f"  0x{i.address - base:x}  {i.mnemonic} {i.op_str}{extra}")
        if i.mnemonic == "ret" or c >= n: break
for cls in ("CBaseEntity", "CBaseAnimating", "CBaseTrigger", "CPointEntity"):
    try:
        w = rows(f"derived/win-vtables/{cls}.txt")
        l = rows(f"derived/linux-vtables/{cls}.txt")
    except Exception as e:
        print(cls, e); continue
    print(f"-- {cls} linux slots 0-1: {l[0][1]} | {l[1][1]}")
    wdis(w[0][0], 40, f"{cls} slot 0")
# every direct call target out of CBaseEntity's slot 0, disassembled
w = rows("derived/win-vtables/CBaseEntity.txt")
va = w[0][0]
for c, i in enumerate(md.disasm(code[va - tva:va - tva + 0x200], va)):
    if i.mnemonic == "call" and i.op_str.startswith("0x"):
        wdis(int(i.op_str, 16), 260, "callee of CBaseEntity slot 0")
    if i.mnemonic == "ret" or c > 40: break

# Linux: _ZN11CBaseEntityD2Ev with its calls named
data = open("game-linux/tf/bin/server_srv.so", "rb").read()
shoff, = struct.unpack_from("<I", data, 0x20); shentsize, shnum = struct.unpack_from("<HH", data, 0x2e)
secs = [struct.unpack_from("<IIIIIIIIII", data, shoff + k * shentsize) for k in range(shnum)]
syms = {}; names = {}
for s in secs:
    if s[1] in (2, 11):
        strtab = secs[s[6]]
        for k in range(s[5] // 16):
            nm, val, sz, info, oth, shn = struct.unpack_from("<IIIBBH", data, s[4] + k * 16)
            if val == 0: continue
            e = data.index(b"\0", strtab[4] + nm); n = data[strtab[4] + nm:e].decode(errors="replace")
            syms[n] = (val, sz); names.setdefault(val, n)
def off(va):
    for s in secs:
        if s[1] == 1 and s[3] <= va < s[3] + s[5]: return s[4] + va - s[3]
def ldis(sym, n):
    va, sz = syms[sym]; o = off(va)
    print(f"== linux {sym} 0x{va:x} size {sz}")
    for c, i in enumerate(md.disasm(data[o:o + sz], va)):
        extra = ""
        if i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x"):
            extra = "    -> " + names.get(int(i.op_str, 16), "?")
        print(f"  0x{i.address:x}  {i.mnemonic} {i.op_str}{extra}")
        if c >= n: break
ldis("_ZN11CBaseEntityD2Ev", 300)
ldis("_ZN11CBaseEntityD0Ev", 40)
PY
