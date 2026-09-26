#!/bin/bash
# Two ranges of slots side by side, Linux name against the head of the
# Windows function, to place three virtuals the pairs are too far from.
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
for cls, lo, hi in [("CEconEntity", 218, 237), ("CTFWeaponBaseGun", 468, 501)]:
    lin = rows(f"derived/linux-vtables/{cls}.txt"); win = rows(f"derived/win-vtables/{cls}.txt")
    print(f"=== {cls}: linux {len(lin)} slots, windows {len(win)}")
    for s in range(lo, hi):
        print(f"  linux {s}: {lin[s][1] if s < len(lin) else '-'}")
    for s in range(lo - 8, min(hi, len(win))):
        print(f"  windows {s}: 0x{win[s][0] - base:x}  {head(win[s][0])}")
PY
