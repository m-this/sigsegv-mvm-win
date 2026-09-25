#!/bin/bash
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
#
# 1. IGameSystem::Add and ::Remove: both dynamic_cast their argument to
#    IGameSystemPerFrame, so both push its RTTI type descriptor.
# 2. Action<CTFBot>'s table, Linux beside Windows, each Windows slot with the
#    head of its body: the bed crashed in the body the table calls
#    Action<CTFBot>::OnLeaveGround (slot 0x33).
python3 - <<'PY'
import re, struct, capstone, pefile, glob
pe = pefile.PE("game-windows/tf/bin/server.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
img = pe.get_memory_mapped_image()
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = text.get_data(); tva = base + text.VirtualAddress
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
def head(va, n=8):
    off = va - tva
    if not 0 <= off < len(code): return "?"
    return "; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in list(md.disasm(code[off:off+0x60], va))[:n])
for name in [b".?AVIGameSystemPerFrame@@", b".?AVIGameSystem@@"]:
    for m in re.finditer(re.escape(name + b"\0"), img):
        td = base + m.start() - 8
        print(f"== {name.decode()} type descriptor 0x{td:08x}")
        seen = set()
        for p in re.finditer(re.escape(b"\x68" + struct.pack("<I", td)), code):
            start = p.start()
            while start > 1 and not (code[start-1] == 0xCC and code[start-2] == 0xCC): start -= 1
            if start in seen: continue
            seen.add(start)
            ins = list(md.disasm(code[start:start+0x300], tva + start))
            rets = [i for i in ins if i.mnemonic == "ret"]
            ret = f"{rets[0].mnemonic} {rets[0].op_str}".strip() if rets else "?"
            calls = [i.op_str for i in ins[:60] if i.mnemonic == "call"]
            print(f"  rva 0x{tva + start - base:x}  first ret: {ret}  size~{(rets[0].address - tva - start) if rets else 0}  calls {calls[:6]}")
            print("    " + head(tva + start, 14))
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
lin = [f for f in glob.glob("derived/linux-vtables/*.txt") if re.search(r"/Action_CTFBot_\.txt$", f)]
win = [f for f in glob.glob("derived/win-vtables/*.txt") if "Action" in f and "CTFBot" in f and "Behavior" not in f]
print("== Action<CTFBot> files", lin, win[:5])
if lin and win:
    w = min(win, key=len)
    L, W = first(lin[0]), first(w)
    print(f"== Action<CTFBot>: linux {len(L)} slots, windows {len(W)} ({w})")
    for i in range(max(len(L), len(W))):
        l = L[i][1] if i < len(L) else ""
        wv = W[i][0] if i < len(W) else 0
        print(f"{i:3d} 0x{i:02x}  {l[:60]:60s}  {wv:08x}  {head(wv, 6) if wv else ''}")
PY
