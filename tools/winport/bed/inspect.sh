#!/bin/bash
# The iterator vtables the crash frames sit in, named from RTTI, each slot
# with the head of its function; and the Linux IEconItemAttributeIterator
# tables for the slot order.
python3 - <<'PY'
import struct, capstone, pefile
pe = pefile.PE("game-windows/tf/bin/server.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
img = pe.get_memory_mapped_image()
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
tlo, thi = text.VirtualAddress, text.VirtualAddress + text.Misc_VirtualSize
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
def d(rva): return struct.unpack_from("<I", img, rva)[0]
def start(rva):
    at = rva
    while not (img[at - 1] in (0xCC, 0x90) and img[at - 2] in (0xCC, 0x90)): at -= 1
    return at
def head(rva, n=8):
    return "; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in list(md.disasm(img[rva:rva + 0x40], base + rva))[:n])
def rtti(vt):
    try:
        col = d(vt - 4) - base; td = d(col + 12) - base
        return img[td + 8:img.index(b"\0", td + 8)].decode()
    except Exception as e: return f"? {e}"
def dump(vt, n=10):
    print(f"-- vtable {vt:#x} {rtti(vt)}")
    for i in range(n):
        f = d(vt + 4 * i) - base
        if not (tlo <= f < thi): break
        print(f"   [{i}] {f:#x}  {head(f)}")
seen = set()
for ret in (0x3c4c7d, 0x3bbae9, 0x3bcaf5, 0x3c4fa4):
    s = start(ret)
    print(f"== return {ret:#x} in function {s:#x}")
    needle = struct.pack("<I", base + s)
    at = img.find(needle)
    while at != -1:
        if not (tlo <= at < thi):
            # walk back to the table start: the slot before it is not code
            vt = at
            while tlo <= d(vt - 4) - base < thi: vt -= 4
            if vt not in seen:
                seen.add(vt); print(f"   referenced at {at:#x} (slot {(at - vt) // 4})"); dump(vt)
        at = img.find(needle, at + 1)
# every vtable whose RTTI name mentions an attribute iterator
print("== RTTI iterator classes")
off = img.find(b".?AV")
names = 0
while off != -1 and names < 400:
    name = img[off:img.index(b"\0", off)]
    if b"Iterat" in name:
        td = off - 8
        # COLs pointing at this type descriptor, then vtables pointing at the COL
        tdp = struct.pack("<I", base + td)
        c = img.find(tdp)
        while c != -1:
            col = c - 12
            if d(col) == 0 and d(col + 4) == 0:
                colp = struct.pack("<I", base + col)
                v = img.find(colp)
                while v != -1:
                    if v + 4 not in seen:
                        seen.add(v + 4); dump(v + 4)
                    v = img.find(colp, v + 1)
            c = img.find(tdp, c + 1)
        names += 1
    off = img.find(b".?AV", off + 1)
PY
echo "== linux"
for f in derived/linux-vtables/*Iterat*; do echo "-- $f"; head -12 "$f"; done
