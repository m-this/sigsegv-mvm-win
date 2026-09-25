#!/bin/bash
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
#
# Action<CTFBot>'s table, Linux beside Windows, each Windows slot with the
# head of its body: the bed crashed in the body the table calls
# Action<CTFBot>::OnLeaveGround (slot 0x33).
ls derived/linux-vtables | grep -i '^Action' | head -20
ls derived/win-vtables | grep -i 'Action' | grep -i ctfbot | head -20
head -3 derived/win-vtables/VCTFBot____Action.txt
python3 - <<'PY'
import re, capstone, pefile, glob
pe = pefile.PE("game-windows/tf/bin/server.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = text.get_data(); tva = base + text.VirtualAddress
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
def head(va, n=6):
    off = va - tva
    if not 0 <= off < len(code): return "?"
    return "; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in list(md.disasm(code[off:off+0x50], va))[:n])
def first(path):
    rows, on = [], False
    for line in open(path):
        if line.startswith("// vtable"):
            if on: break
            on = "offset 0x0000" in line
            continue
        if on and line.startswith("+0x"):
            parts = line.split(None, 2)
            rows.append((int(parts[1], 16), parts[2].strip() if len(parts) > 2 else ""))
    return rows
lin = sorted(glob.glob("derived/linux-vtables/Action_CTFBot*.txt"), key=len)
L = first(lin[0]) if lin else []
W = first("derived/win-vtables/VCTFBot____Action.txt")
print(f"== Action<CTFBot>: linux {len(L)} slots ({lin[:1]}), windows {len(W)}")
for i in range(max(len(L), len(W))):
    l = L[i][1] if i < len(L) else ""
    wv = W[i][0] if i < len(W) else 0
    print(f"{i:3d} 0x{i:02x}  {l[:58]:58s}  {wv:08x}  {head(wv) if wv else ''}")
PY
