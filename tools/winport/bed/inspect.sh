#!/bin/bash
# Who in server.dll asks the server to exit: every push of "exit\n", "quit\n",
# "quit" or "exit", with the instructions before it; and the item schema's
# delayed update, which the boot that exits had just queued.
python3 - <<'PY'
import capstone, pefile
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
pe = pefile.PE("game-windows/tf/bin/server.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
data = pe.__data__
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = text.get_data(); tv = text.VirtualAddress
def start_of(rva):
    at = rva - tv
    while at > 0 and not (code[at-1] in (0xCC, 0x90) and code[at-2] in (0xCC, 0x90)): at -= 1
    return tv + at
def wstr(va):
    try:
        b = pe.get_data(va - base, 120); s = b.split(b"\0")[0]
        return repr(s.decode(errors="replace")) if len(s) >= 3 and all(32 <= c < 127 or c in (9, 10) for c in s) else None
    except Exception:
        return None
def show(ref, before=40, after=12):
    st = start_of(ref)
    ins = list(md.disasm(code[st-tv:ref-tv+80], base + st))
    idx = next((k for k, i in enumerate(ins) if i.address - base >= ref - 1), len(ins))
    print(f"  -- in function {st:#x}")
    for i in ins[max(0, idx-before):idx+after]:
        s = ""
        for tok in i.op_str.replace(",", " ").replace("[", " ").replace("]", " ").split():
            if tok.startswith("0x10"):
                w = wstr(int(tok, 16))
                if w: s += "    " + w
        print(f"    {i.address - base:#x}  {i.mnemonic} {i.op_str}{s}")
def exact(needle):
    at = data.find(needle)
    while at != -1:
        if data[at-1:at] == b"\0" and data[at+len(needle):at+len(needle)+1] == b"\0":
            rva = pe.get_rva_from_offset(at)
            ref = (base + rva).to_bytes(4, "little")
            refs, r = [], code.find(ref)
            while r != -1:
                refs.append(tv + r); r = code.find(ref, r + 1)
            print(f"== {needle!r} at {rva:#x}: {len(refs)} references")
            for x in refs[:12]:
                show(x)
        at = data.find(needle, at + 1)
for n in [b"exit\n", b"quit\n", b"quit", b"exit", b"exit\n\n", b"quit\n\n"]:
    exact(n)
at = data.find(b"update is queued")
while at != -1:
    s = data.rfind(b"\0", 0, at) + 1
    rva = pe.get_rva_from_offset(s)
    ref = (base + rva).to_bytes(4, "little")
    r = code.find(ref)
    name = data[s:data.find(b"\0", s)]
    print(f"== {name!r}")
    while r != -1:
        show(tv + r, 20, 30); r = code.find(ref, r + 1)
    at = data.find(b"update is queued", at + 1)
PY
