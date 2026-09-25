#!/bin/bash
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
# INextBotPlayerInput's vtable in NextBotPlayer<CTFPlayer>: the slots holding the
# release bodies at 0x10561100 (and ~IN_BACK) and 0x10561130 (and ~IN_FORWARD),
# and the 27 slots from where the declaration order puts slot 0.
python3 - <<'PY'
import pefile, struct
pe = pefile.PE("game-windows/tf/bin/server.dll")
base = pe.OPTIONAL_HEADER.ImageBase
for s in pe.sections:
    name = s.Name.rstrip(b"\0").decode()
    if name not in (".rdata", ".data"): continue
    data = s.get_data()
    for target in (0x10561100, 0x10561130):
        at = data.find(struct.pack("<I", target))
        while at != -1:
            if at % 4 == 0:
                va = base + s.VirtualAddress + at
                print(f"{name}: {target:#x} at {va:#x}")
            at = data.find(struct.pack("<I", target), at + 1)
    at = data.find(struct.pack("<I", 0x10561100))
    if at != -1 and at % 4 == 0:
        start = at - 15 * 4
        slots = struct.unpack_from("<27I", data, start)
        col = struct.unpack_from("<I", data, start - 4)[0]
        print(f"vtable guess at {base + s.VirtualAddress + start:#x}, locator {col:#x}")
        for i, v in enumerate(slots):
            print(f"  slot {i:2d}: {v:#x}")
PY
