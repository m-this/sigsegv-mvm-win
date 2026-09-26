#!/bin/bash
# GetConditionProvider, LookupActivity and LookupSequence against Linux, and
# whether any Windows function is PlaySpecificSequence out of line.
python3 - <<'PY'
import re, collections, capstone, pefile
from elftools.elf.elffile import ELFFile

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
elf = ELFFile(open("game-linux/tf/bin/server_srv.so", "rb"))
ltext = elf.get_section_by_name(".text"); lcode = ltext.data(); lva = ltext["sh_addr"]
byaddr, byname = {}, {}
for s in elf.get_section_by_name(".symtab").iter_symbols():
    if s["st_info"]["type"] == "STT_FUNC" and s["st_value"]:
        byaddr.setdefault(s["st_value"], s.name); byname[s.name] = (s["st_value"], s["st_size"])
def ldis(name, limit=80):
    a, n = byname[name]
    print(f"== linux {name} size {n}")
    for k, i in enumerate(md.disasm(lcode[a-lva:a-lva+n], a)):
        line = f"  {i.address:#x}  {i.mnemonic} {i.op_str}"
        if i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x") and int(i.op_str, 16) in byaddr: line += "    -> " + byaddr[int(i.op_str, 16)]
        print(line)
        if k >= limit: break

pe = pefile.PE("game-windows/tf/bin/server.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = text.get_data(); tv = text.VirtualAddress
def wstart(rva):
    at = rva - tv
    while at > 0 and not (code[at-1] in (0xCC, 0x90) and code[at-2] in (0xCC, 0x90)): at -= 1
    return tv + at
wg = collections.defaultdict(set)
at = code.find(b"\xe8")
while at != -1:
    src = tv + at; dst = src + 5 + int.from_bytes(code[at+1:at+5], "little", signed=True)
    if tv <= dst < tv + len(code): wg[dst].add(src)
    at = code.find(b"\xe8", at + 1)
def wdis(start, limit=80):
    print(f"== windows {start:#x}")
    for n, i in enumerate(md.disasm(code[start-tv:start-tv+4000], base + start)):
        line = f"  {i.address-base:#x}  {i.bytes.hex():<16} {i.mnemonic} {i.op_str}"
        if i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x"): line += f"    -> {int(i.op_str, 16)-base:#x}"
        print(line)
        if i.mnemonic == "int3" or n >= limit: break

ldis("_ZN15CTFPlayerShared20GetConditionProviderE7ETFCond")
wdis(0x5218c0)
ldis("_ZN14CBaseAnimating14LookupActivityEPKc")
wdis(0x1cee50)
ldis("_ZN14CBaseAnimating14LookupSequenceEPKc")
wdis(0x1cefb0)
for t in (0x1cee50, 0x1cefb0):
    fs = sorted({wstart(s) for s in wg[t]})
    both = [f for f in fs if any(f <= s < f + 0x400 for s in wg[0x4e8420])]
    print(f"== {len(fs)} callers of {t:#x}; also calling DoAnimationEvent: " + ", ".join(f"{f:#x}" for f in both))
    for f in both:
        if f != 0x4e5040: wdis(f, 50)
PY
