#!/bin/bash
# Tail jumps and calls into CBaseTempEntity::Create (0x434c20), the way the
# Linux TE_TFExplosion ends, with the head of each function holding one; and
# every lea of +0x65c, for SetCustomViewModel's network change.
python3 - <<'PY'
import re, struct, capstone, pefile
pe = pefile.PE("game-windows/tf/bin/server.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = text.get_data(); tva = text.VirtualAddress
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
def start(at):
    while at > 0 and not (code[at - 1] in (0xCC, 0x90) and code[at - 2] in (0xCC, 0x90)): at -= 1
    return at
def head(at, n=12):
    return "; ".join(f"{i.mnemonic} {i.op_str}" for i in list(md.disasm(code[at:at + 0x80], base + tva + at))[:n])
target = 0x434c20 - tva
for at in range(len(code) - 5):
    if code[at] == 0xE9 and at + 5 + struct.unpack_from("<i", code, at + 1)[0] == target:
        f = start(at)
        print(f"== jmp at 0x{tva + at:x} in 0x{tva + f:x}: {head(f)}")
for m in re.finditer(rb"\x8d[\x80-\xbf]\x5c\x06\x00\x00", code):
    ins = next(md.disasm(code[m.start():m.start() + 8], base + tva + m.start()), None)
    if ins and ins.mnemonic == "lea" and "0x65c]" in ins.op_str:
        print(f"== lea at 0x{tva + m.start():x} in 0x{tva + start(m.start()):x}: {ins.op_str}")
PY
