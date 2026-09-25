#!/bin/bash
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
#
# The three virtuals Attr:Custom_Attributes hooks and Windows has no address
# for. The offset-0 tables of the classes it hooks them in, Linux beside
# Windows, each Windows slot named where the committed table knows it.
python3 - <<'PY'
import re
base = 0x10000000
known = {}
t = open("gamedata/sigsegv/windows.txt").read()
for name, body in re.findall(r'"([^"]+)"\s*\{([^{}]*)\}', t):
    m = re.search(r'addr\s+"(0x[0-9a-f]+)"', body)
    if m and 'lib   "server"' in body:
        known.setdefault(base + int(m.group(1), 16), name)
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
for cls in ["CTFWeaponBuilder", "CTFCompoundBow", "CEconEntity"]:
    lin = first(f"derived/linux-vtables/{cls}.txt")
    win = first(f"derived/win-vtables/{cls}.txt")
    print(f"== {cls}: linux {len(lin)} slots, windows {len(win)}")
    for i in range(max(len(lin), len(win))):
        l = lin[i][1] if i < len(lin) else ""
        w = f"{win[i][0]:08x} {known.get(win[i][0], '')}" if i < len(win) else ""
        print(f"{i:4d}  {l[:70]:70s}  {w}")
PY
