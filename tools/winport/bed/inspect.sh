#!/bin/bash
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
#
# PathFollower::PathFollower: every function that writes PathFollower's (or
# Path's) vtable, with its head and how it returns. A constructor takes no
# argument and returns with a plain ret.
python3 - <<'PY'
import re, struct, capstone, pefile
pe = pefile.PE("game-windows/tf/bin/server.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = text.get_data(); tva = base + text.VirtualAddress
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32); md.detail = False
for cls in ["PathFollower", "Path", "ChasePath", "CTFBotFetchFlag"]:
    try:
        first = next(l for l in open(f"derived/win-vtables/{cls}.txt") if l.startswith("// vtable"))
    except (FileNotFoundError, StopIteration):
        print(f"== {cls}: no vtable dump"); continue
    va = int(re.search(r"0x([0-9a-f]+)", first).group(1), 16)
    print(f"== {cls} vtable 0x{va:08x}")
    seen = set()
    for m in re.finditer(re.escape(struct.pack("<I", va)), code):
        at = m.start()
        start = at
        while start > 0 and not (code[start-1] == 0xCC and code[start-2] == 0xCC): start -= 1
        if start in seen: continue
        seen.add(start)
        ins = list(md.disasm(code[start:start+0x400], tva + start))
        rets = [i for i in ins if i.mnemonic == "ret"]
        head = "; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in ins[:10])
        ret = f"{rets[0].mnemonic} {rets[0].op_str}".strip() if rets else "?"
        print(f"  rva 0x{tva + start - base:x}  first ret: {ret}  size~{(rets[0].address - tva - start) if rets else 0}\n    {head}")
PY
