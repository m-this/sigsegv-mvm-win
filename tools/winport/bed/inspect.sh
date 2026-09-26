#!/bin/bash
# GetConditionDuration, PlaySpecificSequence and RemoveCustomAttribute: their
# Linux callers against the Windows ones, and Burn's returns.
python3 - <<'PY'
import re, bisect, collections, capstone, pefile
from elftools.elf.elffile import ELFFile

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
elf = ELFFile(open("game-linux/tf/bin/server_srv.so", "rb"))
ltext = elf.get_section_by_name(".text"); lcode = ltext.data(); lva = ltext["sh_addr"]
got = elf.get_section_by_name(".got.plt")["sh_addr"]
ro = elf.get_section_by_name(".rodata"); rodata = ro.data(); rova = ro["sh_addr"]
byaddr, byname = {}, {}
for s in elf.get_section_by_name(".symtab").iter_symbols():
    if s["st_info"]["type"] == "STT_FUNC" and s["st_value"]:
        byaddr.setdefault(s["st_value"], s.name); byname[s.name] = (s["st_value"], s["st_size"])
def ldis(name, around=None, before=40, after=10):
    a, n = byname[name]
    body = list(md.disasm(lcode[a-lva:a-lva+n], a))
    idx = range(len(body))
    if around:
        hits = [k for k, i in enumerate(body) if i.mnemonic == "call" and i.op_str.startswith("0x") and byaddr.get(int(i.op_str, 16), "") == around]
        idx = sorted({j for k in hits for j in range(max(0, k-before), min(len(body), k+after))})
    print(f"== linux {name} size {n}" + (f" around {around}" if around else ""))
    for k in idx:
        i = body[k]; line = f"  {i.address:#x}  {i.mnemonic} {i.op_str}"
        if i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x") and int(i.op_str, 16) in byaddr: line += "    -> " + byaddr[int(i.op_str, 16)]
        m = re.search(r"\[e[a-d]x ([+-]) (0x[0-9a-f]+)\]", i.op_str)
        if m:
            t = got + (int(m.group(2), 16) * (1 if m.group(1) == "+" else -1))
            if rova <= t < rova + len(rodata): line += "    str " + repr(rodata[t-rova:rodata.find(b"\0", t-rova)][:50].decode(errors="replace"))
        print(line)

pe = pefile.PE("game-windows/tf/bin/server.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = text.get_data(); tv = text.VirtualAddress
def wstart(rva):
    at = rva - tv
    while at > 0 and not (code[at-1] in (0xCC, 0x90) and code[at-2] in (0xCC, 0x90)): at -= 1
    return tv + at
def ins(start, limit=3000):
    out = []
    for n, i in enumerate(md.disasm(code[start-tv:start-tv+40000], base + start)):
        out.append(i)
        if i.mnemonic == "int3" or n >= limit: break
    return out
def show(i):
    line = f"  {i.address-base:#x}  {i.mnemonic} {i.op_str}"
    if i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x"): line += f"    -> {int(i.op_str, 16)-base:#x}"
    return line
def wdis(start, limit=250):
    print(f"== windows {start:#x}")
    for i in ins(start, limit): print(show(i))
def waround(start, target, before=30, after=6):
    body = ins(start)
    hits = [k for k, i in enumerate(body) if i.mnemonic == "call" and i.op_str == hex(base + target)]
    print(f"== windows {start:#x} around calls to {target:#x}")
    for k in sorted({j for h in hits for j in range(max(0, h-before), min(len(body), h+after))}): print(show(body[k]))

# Burn: every return
print("== Burn 0x51a2c0 returns: " + ", ".join(f"{i.address-base:#x} {i.mnemonic} {i.op_str}" for i in ins(0x51a2c0) if i.mnemonic == "ret"))

# RemoveCustomAttribute
ldis("_ZN37CTriggerAddOrRemoveTFPlayerAttributes10StartTouchEP11CBaseEntity")
ldis("_ZN37CTriggerAddOrRemoveTFPlayerAttributes8EndTouchEP11CBaseEntity")
ldis("_ZN11CTFLunchBox6DetachEv", around="_ZN9CTFPlayer21RemoveCustomAttributeEPKc", before=15)
wdis(0x541e60, 120)
wdis(0x50a220, 160)

# PlaySpecificSequence
ldis("_ZN9CTFPlayer13ClientCommandERK8CCommand", around="_ZN9CTFPlayer20PlaySpecificSequenceEPKc", before=25)
ldis("_ZN19CTFBotMvMDeployBomb6UpdateEP6CTFBotf", around="_ZN9CTFPlayer20PlaySpecificSequenceEPKc", before=20)
waround(0x4e5040, 0x4e8420)

# GetConditionDuration
ldis("_ZN11CTFAmmoPack9PackTouchEP11CBaseEntity", around="_ZNK15CTFPlayerShared20GetConditionDurationE7ETFCond", before=25, after=15)
print("== small functions returning a float at cond*20+8")
for m in re.finditer(rb"\x8d\x04\x80|\x8d\x04\x89|\x8d\x04\x92|\x8d\x04\x9b|\x8d\x04\xb6|\x8d\x04\xbf|\x8d\x0c\x89|\x8d\x0c\xb6|\x8d\x0c\xbf|\x8d\x0c\x80", code):
    f = wstart(tv + m.start())
    if tv + m.start() - f > 0x80: continue
    body = ins(f, 60)
    txt = [f"{i.mnemonic} {i.op_str}" for i in body]
    if len(body) < 60 and any("*4 + 8]" in t and ("fld" in t or "movss" in t) for t in txt) and "ret 4" in txt:
        print(f"  {f:#x}: " + "; ".join(txt))
PY
