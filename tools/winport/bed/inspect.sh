#!/bin/bash
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
#
# IGameSystem::Add and ::Remove: both dynamic_cast their argument to
# IGameSystemPerFrame, so both push its RTTI type descriptor. Every function
# that does, with its head, its size and how it returns.
python3 - <<'PY'
import re, struct, capstone, pefile
pe = pefile.PE("game-windows/tf/bin/server.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
img = pe.get_memory_mapped_image()
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = text.get_data(); tva = base + text.VirtualAddress
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
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
            print("    " + "; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in ins[:14]))
PY
