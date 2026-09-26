#!/bin/bash
# Each virtual's Windows slot, predicted from the nearest pair the tables
# already agree on below and above it, with the function each candidate slot
# holds disassembled, to be read against the Linux body.
python3 - <<'PY'
import re, capstone, pefile
pe = pefile.PE("game-windows/tf/bin/server.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = text.get_data(); tva = base + text.VirtualAddress
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
known = {}
cur = None
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
for cls, fn in [("CBasePlayer", "Weapon_ShootPosition"), ("CEconEntity", "ReapplyProvision"),
                ("CTFWeaponBaseGun", "GetProjectileSpeed"), ("CTFWeaponBaseGun", "GetWeaponProjectileType")]:
    lin = rows(f"derived/linux-vtables/{cls}.txt"); win = rows(f"derived/win-vtables/{cls}.txt")
    target = next(s for s, a, n in lin if f"::{fn}(" in n)
    pairs = []
    for s, a, n in lin:
        m = re.match(r'(\w+)::(\w+)\(', n)
        if not m: continue
        for k, w in known.items():
            if k.endswith("::" + m.group(2)) and k.split("::")[0] in (cls, m.group(1)):
                pairs.append((s, w, n)); break
    below = [p for p in pairs if p[0] < target][-2:]; above = [p for p in pairs if p[0] > target][:2]
    print(f"=== {cls}::{fn}: linux slot {target}; windows table {len(win)} slots, linux {len(lin)}")
    for s, w, n in below + above: print(f"  pair linux {s} windows {w} (shift {s - w}) {n}")
    shifts = sorted({s - w for s, w, n in below + above})
    for sh in shifts:
        slot = target - sh
        if not 0 <= slot < len(win): continue
        va = win[slot][1]
        print(f"  shift {sh}: windows slot {slot} -> 0x{va - base:x}")
        for i in list(md.disasm(code[va - tva:va - tva + 0x50], va))[:14]:
            print(f"      {i.mnemonic} {i.op_str}")
PY
