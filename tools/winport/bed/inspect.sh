#!/bin/bash
# Weapon_Detach has no match of its own: Weapon_Drop calls it. Weapon_Drop's
# Windows slot in CTFPlayer's table from the pairs around it, and the direct
# calls its body makes. DetonateObject's slot in CBaseObject's the same way.
python3 - <<'PY'
import re, capstone, pefile
pe = pefile.PE("game-windows/tf/bin/server.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = text.get_data(); tva = base + text.VirtualAddress
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
known = {}; cur = None
for line in open("tools/winport/knownvtidx.generated.txt"):
    m = re.match(r'^"([^"]+)"', line)
    if m: cur = m.group(1)
    m = re.search(r'idx\s+"(\d+)"', line)
    if m and cur: known[cur] = int(m.group(1))
def rows(path):
    out = []
    for l in open(path):
        if l.startswith("// vtable") and "offset 0x0000" not in l: break
        m = re.match(r'\+0x([0-9a-f]+):\s+([0-9a-f]+)\s*(.*)', l)
        if m: out.append((int(m.group(1), 16) // 4, int(m.group(2), 16), m.group(3).strip()))
    return out
def body(va, n=90):
    return list(md.disasm(code[va - tva:va - tva + 0x400], va))[:n]
for cls, fn in [("CBaseCombatCharacter", "Weapon_Drop"), ("CObjectSentrygun", "DetonateObject")]:
    import os
    if not os.path.exists(f"derived/linux-vtables/{cls}.txt") or not os.path.exists(f"derived/win-vtables/{cls}.txt"):
        print(f"=== {cls}: no table", [f for f in os.listdir("derived/win-vtables") if cls[1:8] in f][:8]); continue
    lin = rows(f"derived/linux-vtables/{cls}.txt"); win = rows(f"derived/win-vtables/{cls}.txt")
    hits = [s for s, a, n in lin if f"::{fn}(" in n]
    if not hits: print(f"=== {cls}::{fn}: not in the Linux table"); continue
    target = hits[0]
    pairs = []
    for s, a, n in lin:
        m = re.match(r'(\w+)::(\w+)\(', n)
        if not m: continue
        for k, w in known.items():
            if k.endswith("::" + m.group(2)) and k.split("::")[0] in (cls, m.group(1)):
                pairs.append((s, w, n)); break
    below = [p for p in pairs if p[0] < target][-3:]; above = [p for p in pairs if p[0] > target][:3]
    print(f"=== {cls}::{fn}: linux slot {target} ({lin[target][2]}); windows {len(win)} slots, linux {len(lin)}")
    for s, w, n in below + above: print(f"  pair linux {s} windows {w} (shift {s - w}) {n}")
    for sh in sorted({s - w for s, w, n in below + above}):
        slot = target - sh
        if not 0 <= slot < len(win): continue
        va = win[slot][1]
        insns = body(va)
        calls = [f"0x{int(i.op_str, 16) - base:x}" for i in insns if i.mnemonic == "call" and i.op_str.startswith("0x")]
        print(f"  shift {sh}: slot {slot} -> 0x{va - base:x}; first: " + "; ".join(f"{i.mnemonic} {i.op_str}" for i in insns[:8]))
        print(f"    direct calls: {' '.join(calls)}")
PY
