#!/bin/bash
# Every store to a word at +0x65c in server.dll (m_nCustomViewmodelModelIndex
# if Linux's +0x668 moves by 0xc as m_hWeaponFileInfo does), for
# SetCustomViewModel, and the functions holding them.
python3 - <<'PY'
import re, capstone, pefile
pe = pefile.PE("game-windows/tf/bin/server.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = text.get_data(); tva = text.VirtualAddress
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
def start(at):
    while at > 0 and not (code[at - 1] in (0xCC, 0x90) and code[at - 2] in (0xCC, 0x90)): at -= 1
    return at
pat = re.compile(rb"\x66(?:\x89|\xc7|\x39|\x3b|\x83|\x8b)[\x80-\xbf]\x5c\x06\x00\x00|\x0f[\xb7\xbf][\x80-\xbf]\x5c\x06\x00\x00", re.S)
seen = {}
for m in pat.finditer(code):
    at = m.start()
    ins = next(md.disasm(code[at:at + 16], base + tva + at), None)
    if not ins or "0x65c]" not in ins.op_str: continue
    f = start(at)
    seen.setdefault(f, []).append(f"0x{tva + at:x} {ins.mnemonic} {ins.op_str}")
for f, l in sorted(seen.items()):
    print(f"== in 0x{tva + f:x}: " + "; ".join(l))
PY
