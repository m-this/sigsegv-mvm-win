#!/bin/bash
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
# CEconEntity::GiveTo (Linux +0x390) and CTFBaseBoss::UpdateCollisionBounds
# (Linux +0x54c) are empty on Linux; their Windows slots by alignment, with the
# first bytes of each slot's function, for the classes and a derived one each.
for c in CEconEntity CTFWearable CTFBaseBoss CTFTankBoss; do
  echo "== linux $c"; grep -n "" "derived/linux-vtables/$c.txt" | sed -n '/+0x0370:/,/+0x03b0:/p;/+0x0530:/,/+0x0570:/p' | head -40
done
python3 - <<'PY'
import pefile, struct, re, glob
pe = pefile.PE("game-windows/tf/bin/server.dll")
base = pe.OPTIONAL_HEADER.ImageBase
def rd(va, n): return pe.get_data(va - base, n)
for c, lo, hi in (("CEconEntity", 228, 246), ("CTFWearable", 228, 246), ("CTFBaseBoss", 336, 356), ("CTFTankBoss", 336, 356)):
    f = f"derived/win-vtables/{c}.txt"
    try: head = open(f).read(400)
    except OSError: print("no", f); continue
    m = re.search(r"vtable at (0x[0-9a-f]+) offset 0x0000", head)
    vt = int(m.group(1), 16)
    print(f"== windows {c} vtable {vt:#x}")
    for i in range(lo, hi):
        fn = struct.unpack("<I", rd(vt + 4 * i, 4))[0]
        try: b = rd(fn, 8).hex(" ")
        except Exception: b = "?"
        print(f"  slot {i} (+{4*i:#x}): {fn:#x}  {b}")
PY
