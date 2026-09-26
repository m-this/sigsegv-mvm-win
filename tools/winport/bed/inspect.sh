#!/bin/bash
# CObjectSentrygun's slots around DetonateObject, Linux names against the
# heads of the Windows functions.
python3 - <<'PY'
import re, capstone, pefile
pe = pefile.PE("game-windows/tf/bin/server.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = text.get_data(); tva = base + text.VirtualAddress
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
def rows(path):
    out = []
    for l in open(path):
        if l.startswith("// vtable") and "offset 0x0000" not in l: break
        m = re.match(r'\+0x([0-9a-f]+):\s+([0-9a-f]+)\s*(.*)', l)
        if m: out.append((int(m.group(2), 16), m.group(3).strip()))
    return out
def head(va):
    return "; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in list(md.disasm(code[va - tva:va - tva + 0x30], va))[:5])
lin = rows("derived/linux-vtables/CObjectSentrygun.txt"); win = rows("derived/win-vtables/CObjectSentrygun.txt")
for s in range(344, 366): print(f"  linux {s}: {lin[s][1]}")
for s in range(336, 360): print(f"  windows {s}: 0x{win[s][0] - base:x}  {head(win[s][0])}")
PY
