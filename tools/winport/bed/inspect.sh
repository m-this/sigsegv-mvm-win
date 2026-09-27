#!/bin/bash
# The code around each call of the CTFGameRules constructor and of
# VScriptServerInit: whether the caller reads eax/al after the call.
python3 - <<'PY'
import capstone, pefile
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
pe = pefile.PE("game-windows/tf/bin/server.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = text.get_data(); tv = text.VirtualAddress
for want in (0x47ad50, 0x38a790):
    at = code.find(b"\xe8")
    while at != -1:
        if at + 5 <= len(code) and tv + at + 5 + int.from_bytes(code[at+1:at+5], "little", signed=True) == want:
            print(f"== call {want:#x} at {tv+at:#x}")
            for i in md.disasm(code[at-40:at+60], base + tv + at - 40):
                print(f"   {i.address-base:#x}  {i.mnemonic} {i.op_str}")
        at = code.find(b"\xe8", at + 1)
PY
