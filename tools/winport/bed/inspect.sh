#!/bin/bash
# Where the start of the function holding 0x4d1e1d is taken as an immediate
# (the think pointer SetContextThink stores), and the head of each holder.
python3 - <<'PY'
import re, struct, capstone, pefile
pe = pefile.PE("game-windows/tf/bin/server.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = text.get_data(); tva = base + text.VirtualAddress
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
at = 0x4d1e1d - text.VirtualAddress
while not (code[at - 1] == 0xcc and code[at - 2] == 0xcc): at -= 1
start = tva + at
print(f"  function start 0x{start - base:x}")
for m in re.finditer(re.escape(struct.pack("<I", start)), code):
    h = tva + m.start()
    for back in range(1, 12):
        ins = list(md.disasm(code[m.start() - back:m.start() + 8], h - back))
        if ins and ins[0].address + ins[0].size > h:
            print(f"  immediate at 0x{h - base:x}: {ins[0].mnemonic} {ins[0].op_str}"); break
PY
