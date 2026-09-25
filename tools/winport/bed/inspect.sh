#!/bin/bash
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
#
# g_aPlayerClassNames_NonLocalized: an array of pointers to "Undefined",
# "Scout", "Sniper", ... Every array of pointers in server.dll whose entries 1
# to 9 name the nine classes, with what each entry points to.
python3 - <<'PY'
import struct, pefile
pe = pefile.PE("game-windows/tf/bin/server.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
img = pe.get_memory_mapped_image()
def cstr(va):
    off = va - base
    if not 0 <= off < len(img): return None
    end = img.find(b"\0", off, off + 64)
    return img[off:end].decode("latin1") if end > 0 else None
classes = ["scout", "sniper", "soldier", "demoman", "medic", "heavy", "pyro", "spy", "engineer"]
for sec in pe.sections:
    name = sec.Name.rstrip(b"\0").decode()
    if name not in (".data", ".rdata"): continue
    start = sec.VirtualAddress
    data = img[start:start + sec.Misc_VirtualSize]
    for off in range(0, len(data) - 13 * 4, 4):
        ptrs = struct.unpack_from("<13I", data, off)
        names = [cstr(p) for p in ptrs[1:10]]
        if all(n and n.lower().startswith(c) for n, c in zip(names, classes)):
            print(f"{name} rva 0x{start + off:x}: " + ", ".join(repr(cstr(p)) for p in ptrs))
PY
