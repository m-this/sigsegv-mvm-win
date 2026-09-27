# side by side: python3 side.py CLASS FROM TO   (Windows indices), run in derived/
import sys, re
from pathlib import Path
sys.path.insert(0, "../tools/winport")
import matchvtables as mv
import pefile, capstone
pe = pefile.PE("../game-windows/tf/bin/server.dll", fast_load=True)
img = pe.get_memory_mapped_image()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
def head(va, n=60):
    rva = va - 0x10000000
    out, pops = [], None
    for ins in md.disasm(img[rva:rva + 400], va):
        out.append(f"{ins.mnemonic} {ins.op_str}".strip())
        if ins.mnemonic == "ret":
            pops = int(ins.op_str, 16) if ins.op_str else 0
            break
        if len(out) >= n:
            break
    return pops, out
corpus = mv.Corpus("linux-vtables")
cls, lo, hi = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
linux = corpus.tables[cls]
win = mv.read_windows(Path(f"win-vtables/{cls}.txt"))[0]
_, new = mv.align(linux, win, corpus.order(cls))
_, old = mv.align(linux, win)
new = new or mv.collapse_destructors([linux[i] for i in corpus.order(cls)])
old = old or mv.collapse_destructors(linux)
print(f"--- {cls}: linux {len(linux)} win {len(win)}")
for i in range(lo, min(hi + 1, len(win))):
    pops, ins = head(win[i], 10)
    o = old[i] if i < len(old) else "-"
    n = new[i] if i < len(new) else "-"
    mark = "  " if o == n else "* "
    print(f"{mark}{i:4d} {win[i]-0x10000000:#08x} ret {pops}  new {n}   | old {o}")
    print(f"        {' ; '.join(ins)}")
