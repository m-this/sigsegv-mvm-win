#!/bin/bash
# Questions for the address job that need its derived files, rewritten for each
# investigation like disasm.txt. Runs from the repository root after the table
# is derived; the dumps are under derived/.
#
# Action<CZombie>'s destructor: slot 0 of its table is the scalar deleting
# destructor; the destructor proper is the first function it calls.
ls derived/win-vtables | grep -i 'czombie' | grep -i action
python3 - <<'PY'
import re, capstone, pefile
pe = pefile.PE("game-windows/tf/bin/server.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = text.get_data(); tva = base + text.VirtualAddress
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
for f in ["VCZombie____Action.txt", "VCTFBot____Action.txt"]:
    try: rows = [l for l in open("derived/win-vtables/" + f) if l.startswith("+0x0000:")]
    except FileNotFoundError: print("no", f); continue
    va = int(rows[0].split()[1], 16)
    print(f"== {f} slot 0 at rva 0x{va - base:x}")
    for i in list(md.disasm(code[va - tva:va - tva + 0x60], va))[:14]:
        print(f"  0x{i.address - base:x}  {i.mnemonic} {i.op_str}")
PY
